package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"binaryscan.local/backend/internal/job"
)

func TestJavaProjectProgressIsPolledDuringSynchronousAnalysis(t *testing.T) {
	polled := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/analyze":
			select {
			case <-polled:
				_, _ = w.Write([]byte(`{"result":"completed"}`))
			case <-r.Context().Done():
			}
		case "/progress":
			_, _ = w.Write([]byte(`{"version":"java-project-v1","phase":"analyzing","current":11,"total":18}`))
			// Do not finish /analyze until Go has consumed this body: otherwise
			// cancellation may race the first legitimate progress response.
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ctx = job.WithProgressSink(ctx, func(value job.Progress) {
		if value.Phase == "analyzing" && value.Current == 11 && value.Total == 18 {
			once.Do(func() { close(polled) })
		}
	})
	session := &javaProjectSession{client: server.Client(), endpoint: server.URL}
	if _, err := javaProjectAnalyzeCall(ctx, session); err != nil {
		t.Fatal(err)
	}
}

func TestJavaProgressRejectsInvalidCountersAndKeepsPublicationPending(t *testing.T) {
	var updates []job.Progress
	ctx := job.WithProgressSink(context.Background(), func(value job.Progress) { updates = append(updates, value) })
	for _, body := range []string{
		`{"version":"java-project-v1","phase":"analyzing","current":19,"total":18}`,
		`{"version":"unknown","phase":"analyzing","current":11,"total":18}`,
		`{"version":"java-project-v1","phase":"analyzing","current":-1,"total":18}`,
		`{"version":"java-project-v1","phase":"completed","current":18,"total":18}`,
	} {
		reportJavaProgress(ctx, []byte(body))
	}
	if len(updates) != 1 || updates[0].Phase != "analyzing" || updates[0].Current != 18 {
		t.Fatalf("accepted invalid counter or prematurely marked Go publication completed: %+v", updates)
	}
}
