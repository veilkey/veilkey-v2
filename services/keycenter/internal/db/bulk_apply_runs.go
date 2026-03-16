package db

import (
	"fmt"
	"strings"
)

func normalizeBulkApplyRun(run *BulkApplyRun) error {
	if run == nil {
		return fmt.Errorf("bulk apply run is required")
	}
	run.RunID = strings.TrimSpace(run.RunID)
	run.VaultRuntimeHash = strings.TrimSpace(run.VaultRuntimeHash)
	run.WorkflowName = strings.TrimSpace(run.WorkflowName)
	run.RunKind = strings.TrimSpace(run.RunKind)
	run.Status = strings.TrimSpace(run.Status)
	if run.RunID == "" {
		return fmt.Errorf("run_id is required")
	}
	if run.VaultRuntimeHash == "" {
		return fmt.Errorf("vault_runtime_hash is required")
	}
	if run.WorkflowName == "" {
		return fmt.Errorf("workflow_name is required")
	}
	if run.RunKind == "" {
		return fmt.Errorf("run_kind is required")
	}
	if run.Status == "" {
		return fmt.Errorf("status is required")
	}
	if strings.TrimSpace(run.SummaryJSON) == "" {
		run.SummaryJSON = "{}"
	}
	return nil
}

func (d *DB) SaveBulkApplyRun(run *BulkApplyRun) error {
	if err := normalizeBulkApplyRun(run); err != nil {
		return err
	}
	return d.conn.Save(run).Error
}

func (d *DB) ListBulkApplyRuns(vaultRuntimeHash, workflowName string, limit int) ([]BulkApplyRun, error) {
	if limit <= 0 {
		limit = 10
	}
	var out []BulkApplyRun
	query := d.conn.Where("vault_runtime_hash = ?", strings.TrimSpace(vaultRuntimeHash))
	if strings.TrimSpace(workflowName) != "" {
		query = query.Where("workflow_name = ?", strings.TrimSpace(workflowName))
	}
	if err := query.Order("created_at DESC").Limit(limit).Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) GetBulkApplyRun(runID string) (*BulkApplyRun, error) {
	var run BulkApplyRun
	if err := d.conn.First(&run, "run_id = ?", strings.TrimSpace(runID)).Error; err != nil {
		return nil, fmt.Errorf("bulk apply run %s not found", strings.TrimSpace(runID))
	}
	return &run, nil
}
