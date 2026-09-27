<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextKeyDeriver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\SequentialChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class SequentialChunkAnalyzerTest extends TestCase
{
    /**
     * A run whose every chunk failed learned nothing, so there is no partial
     * result worth keeping. Reporting it as a clean audit would be a false
     * all-clear, so the last provider failure is rethrown instead.
     *
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     */
    public function test_it_rethrows_when_every_chunk_failed_so_a_dead_llm_never_reports_an_all_clear(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willThrowException(new LLMProviderException('platform gone'));

        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        try {
            $this->makeAnalyzer($llmClient)->analyze(
                [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
                $this->request(),
                $recordingCoverageRecorder,
                null,
                new RiskMarkerIndex([]),
            );
            self::fail('expected LLMProviderException');
        } catch (LLMProviderException) {
            self::assertSame(
                [
                    ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                    ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'errored'],
                ],
                $recordingCoverageRecorder->coverage,
            );
        }
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_keeps_analyzing_after_one_chunk_fails_and_returns_the_other_chunks_findings(): void
    {
        $calls = 0;
        $llmClient = self::createMock(LLMClientInterface::class);
        $llmClient->expects(self::exactly(2))
            ->method('complete')
            ->willReturnCallback(function () use (&$calls): LLMResponse {
                ++$calls;
                if (1 === $calls) {
                    throw new LLMProviderException('platform gone');
                }

                return LLMResponse::of($this->findingPayload(), 'claude', 'end_turn', TokenUsageSnapshot::of(100, 200));
            });

        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        [$vulnerabilities] = $this->makeAnalyzer($llmClient)->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
            $this->request(),
            $recordingCoverageRecorder,
            null,
            new RiskMarkerIndex([]),
        );

        self::assertCount(1, $vulnerabilities);
        self::assertSame('Missing access control', $vulnerabilities[0]->title());
        self::assertSame(
            [
                ['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored'],
                ['stage' => 'attacker', 'filePath' => 'src/B.php', 'status' => 'analyzed'],
            ],
            $recordingCoverageRecorder->coverage,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     */
    /**
     * @throws BudgetExceededException
     * @throws InvalidProjectFileException
     * @throws LLMProviderException
     */
    public function test_it_logs_a_warning_when_a_chunk_fails_and_the_audit_continues(): void
    {
        $calls = 0;
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturnCallback(static function () use (&$calls): LLMResponse {
            ++$calls;
            if (1 === $calls) {
                throw new LLMProviderException('platform gone');
            }

            return LLMResponse::of('', 'claude', 'end_turn', TokenUsageSnapshot::of(1, 1));
        });

        $logger = self::createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('the audit continues'),
                self::callback(static fn (array $context): bool => 'platform gone' === ($context['error'] ?? null)),
            );

        $this->makeAnalyzer($llmClient, $logger)->analyze(
            [[$this->makeFile('src/A.php')], [$this->makeFile('src/B.php')]],
            $this->request(),
            new RecordingCoverageRecorder(),
            null,
            new RiskMarkerIndex([]),
        );
    }

    private function makeAnalyzer(LLMClientInterface $llmClient, ?LoggerInterface $logger = null): SequentialChunkAnalyzer
    {
        return new SequentialChunkAnalyzer(
            $llmClient,
            new ChunkContextFactory(new AttackerPromptBuilder(), new NullCodeSlicer(), new AttackerContextPromptRenderer(), new ChunkContextKeyDeriver()),
            new AttackerChunkCache(new NullAttackerCache(), $this->vulnerabilityFactory(), new NullLogger()),
            $this->vulnerabilityFactory(),
            $logger ?? new NullLogger(),
            new NullProgressReporter(),
            3,
            false,
            null,
        );
    }

    private function request(): AttackerAnalysisRequest
    {
        return new AttackerAnalysisRequest([], SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap()));
    }

    private function findingPayload(): string
    {
        return (string) json_encode([[
            'type' => 'broken_access_control',
            'severity' => 'critical',
            'title' => 'Missing access control',
            'description' => 'Controller exposes admin route without voter',
            'file_path' => 'src/B.php',
            'line_start' => 10,
            'line_end' => 20,
            'vulnerable_code' => 'public function adminAction()',
            'attack_vector' => 'Direct URL access',
            'proof' => 'GET /admin/users',
            'remediation' => 'Add #[IsGranted("ROLE_ADMIN")]',
            'confidence' => 0.9,
        ]]);
    }

    private function vulnerabilityFactory(): VulnerabilityFactory
    {
        return new VulnerabilityFactory(new NullLogger(), Validation::createValidator());
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }
}
