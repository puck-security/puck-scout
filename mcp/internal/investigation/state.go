package investigation

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Phase string

const (
	PhasePathfinder Phase = "pathfinder"
	PhaseFleet      Phase = "fleet"
	PhaseFollowup   Phase = "followup"
	PhaseAnalysis   Phase = "analysis"
	PhaseComplete   Phase = "complete"
)

type Investigation struct {
	ID           string
	Query        string
	Skill        string
	Phase        Phase
	Turn         int
	MaxTurns     int
	CommandCount int
	MaxCommands  int
	StartedAt    time.Time
	Dir          string
}

type Manager struct {
	mu              sync.RWMutex
	investigations  map[string]*Investigation
	baseDir         string
	defaultMaxTurns int
	defaultMaxCmds  int
	maxActive       int // 0 = no limit
}

// NewManager creates a new Manager with the given base directory and defaults.
// maxActive caps the number of concurrent investigations; 0 means no limit.
func NewManager(baseDir string, maxTurns, maxCommands, maxActive int) *Manager {
	return &Manager{
		investigations:  make(map[string]*Investigation),
		baseDir:         baseDir,
		defaultMaxTurns: maxTurns,
		defaultMaxCmds:  maxCommands,
		maxActive:       maxActive,
	}
}

// Create initialises a new Investigation and stores it in the manager.
func (m *Manager) Create(query, skill string) (*Investigation, error) {
	m.mu.Lock()
	if m.maxActive > 0 && len(m.investigations) >= m.maxActive {
		m.mu.Unlock()
		return nil, fmt.Errorf("maximum concurrent investigations (%d) reached", m.maxActive)
	}
	m.mu.Unlock()

	id := uuid.New().String()
	inv := &Investigation{
		ID:          id,
		Query:       query,
		Skill:       skill,
		Phase:       PhasePathfinder,
		Turn:        0,
		MaxTurns:    m.defaultMaxTurns,
		MaxCommands: m.defaultMaxCmds,
		StartedAt:   time.Now(),
		Dir:         filepath.Join(m.baseDir, id),
	}

	m.mu.Lock()
	m.investigations[id] = inv
	m.mu.Unlock()

	return inv, nil
}

// Get returns a snapshot of the Investigation with the given ID.
// A value copy is returned so callers hold an immutable snapshot
// rather than a shared pointer that races with SetPhase/IncrementTurn.
func (m *Manager) Get(id string) (Investigation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inv, ok := m.investigations[id]
	if !ok {
		return Investigation{}, fmt.Errorf("investigation %q not found", id)
	}
	return *inv, nil
}

// IncrementCommands adds count to the command counter for the given investigation.
// It returns an error if the new total would exceed MaxCommands.
func (m *Manager) IncrementCommands(id string, count int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.investigations[id]
	if !ok {
		return fmt.Errorf("investigation %q not found", id)
	}

	next := inv.CommandCount + count
	if next > inv.MaxCommands {
		return fmt.Errorf("investigation %q: command cap exceeded (%d > %d)", id, next, inv.MaxCommands)
	}
	inv.CommandCount = next
	return nil
}

// SetPhase updates the phase of the given investigation.
func (m *Manager) SetPhase(id string, phase Phase) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.investigations[id]
	if !ok {
		return fmt.Errorf("investigation %q not found", id)
	}
	inv.Phase = phase
	return nil
}

// IncrementTurn increments the turn counter and returns the new value.
func (m *Manager) IncrementTurn(id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.investigations[id]
	if !ok {
		return 0, fmt.Errorf("investigation %q not found", id)
	}
	inv.Turn++
	return inv.Turn, nil
}

// ExtendBudget adds more commands to an investigation's budget.
func (m *Manager) ExtendBudget(id string, additional int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, ok := m.investigations[id]
	if !ok {
		return 0, fmt.Errorf("investigation %q not found", id)
	}
	inv.MaxCommands += additional
	return inv.MaxCommands, nil
}

// Status returns a summary of the investigation's current state.
func (m *Manager) Status(id string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	inv, ok := m.investigations[id]
	if !ok {
		return nil, fmt.Errorf("investigation %q not found", id)
	}
	return map[string]any{
		"investigation_id":   inv.ID,
		"phase":              string(inv.Phase),
		"turn":               inv.Turn,
		"max_turns":          inv.MaxTurns,
		"commands_used":      inv.CommandCount,
		"max_commands":       inv.MaxCommands,
		"commands_remaining": inv.MaxCommands - inv.CommandCount,
		"query":              inv.Query,
		"skill":              inv.Skill,
	}, nil
}
