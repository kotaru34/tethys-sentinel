package workerclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kotaru34/tethys-sentinel/internal/executionjob"
	"github.com/kotaru34/tethys-sentinel/internal/executionoutput"
	"github.com/kotaru34/tethys-sentinel/internal/internalapi"
)

func (c *Client) CompleteWithOutput(ctx context.Context, workerID string, claim executionjob.Claim, result executionjob.Result, output executionoutput.Output) (executionjob.Job, error) {
	if err := executionoutput.Validate(output); err != nil {
		return executionjob.Job{}, err
	}
	body, err := json.Marshal(internalapi.CompleteExecutionJobRequest{
		WorkerID: workerID, ClaimToken: claim.ClaimToken, Result: result, Output: output,
	})
	if err != nil {
		return executionjob.Job{}, err
	}
	resp, err := c.post(ctx, "/internal/v1/execution/jobs/"+claim.Job.ID+"/complete", body)
	if err != nil {
		return executionjob.Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return executionjob.Job{}, fmt.Errorf("execution job completion rejected with status %d", resp.StatusCode)
	}
	var out internalapi.CompleteExecutionJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return executionjob.Job{}, err
	}
	return out.Job, nil
}
