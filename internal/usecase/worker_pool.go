package usecase

import (
	"context"
	"log"
	"sync"
	"time"
)

type AsyncTaskType string

const (
	TaskTypeAuditLog    AsyncTaskType = "AUDIT_LOG"
	TaskTypeEmailNotify AsyncTaskType = "EMAIL_NOTIFICATION"
)

type AsyncTaskJob struct {
	Type       AsyncTaskType
	CustomerID string
	Payload    map[string]interface{}
	CreatedAt  time.Time
}

type WorkerPool struct {
	jobChan    chan AsyncTaskJob
	workerCount int
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewWorkerPool(workerCount int, bufferSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	pool := &WorkerPool{
		jobChan:     make(chan AsyncTaskJob, bufferSize),
		workerCount: workerCount,
		ctx:         ctx,
		cancel:      cancel,
	}
	pool.start()
	return pool
}

func (p *WorkerPool) start() {
	for i := 1; i <= p.workerCount; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
	log.Printf("[WorkerPool] Initialized %d background workers", p.workerCount)
}

func (p *WorkerPool) worker(workerID int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			// Process remaining jobs in channel before exiting if closed
			for job := range p.jobChan {
				p.processJob(workerID, job)
			}
			return
		case job, ok := <-p.jobChan:
			if !ok {
				return
			}
			p.processJob(workerID, job)
		}
	}
}

func (p *WorkerPool) processJob(workerID int, job AsyncTaskJob) {
	switch job.Type {
	case TaskTypeAuditLog:
		log.Printf("[Worker %d][AUDIT LOG] CustomerID: %s registered successfully at %v",
			workerID, job.CustomerID, job.CreatedAt)
	case TaskTypeEmailNotify:
		log.Printf("[Worker %d][EMAIL NOTIFICATION] Sending registration status PENDING_VERIFICATION email to CustomerID: %s",
			workerID, job.CustomerID)
	default:
		log.Printf("[Worker %d][UNKNOWN TASK] Received unknown job type: %s", workerID, job.Type)
	}
}

func (p *WorkerPool) Enqueue(job AsyncTaskJob) bool {
	select {
	case p.jobChan <- job:
		return true
	default:
		log.Printf("[WorkerPool Warning] Job buffer full! Dropping job: %s for CustomerID: %s", job.Type, job.CustomerID)
		return false
	}
}

func (p *WorkerPool) Shutdown(ctx context.Context) {
	log.Println("[WorkerPool] Initiating worker pool graceful shutdown...")
	p.cancel()
	close(p.jobChan)

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[WorkerPool] All workers stopped cleanly.")
	case <-ctx.Done():
		log.Println("[WorkerPool Warning] Worker pool shutdown timed out.")
	}
}
