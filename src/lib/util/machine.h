

typedef struct fr_machine_s fr_machine_t;

typedef int (*fr_machine_func_t)(fr_machine_t *m, void *rctx);

typedef int (*fr_machine_transition_t)(fr_machine_t *m, void *rctx, int next);

typedef void (*fr_machine_signal_t)(fr_machine_t *m, void *rctx, int signal);

typedef struct {
	char const		*name;			//!< state name
	uint64_t		allowed;		//!< bit mask of allowed transitions into this state
	fr_machine_func_t	process;		//!< run this to process the current state
	fr_machine_func_t	enter;			//!< run this when entering the state
	fr_machine_func_t	exit;			//!< run this when exiting the state
	fr_machine_transition_t transition;		//!< called when transitioning from one state to another
	fr_machine_signal_t	signal;			//!< send a signal to the current state
} fr_machine_edge_t;

typedef struct fr_machine_s fr_machine_t;

struct fr_machine_s {
	int			max_state;		//!< maximum state number
	int			max_signal;		//!< maximum signal which is allowed

	fr_machine_fun_t	fail;			//!< run only when there is an internal failure.
	fr_machine_edge_t const	*edge;			//!< edges for each state
};

typedef struct {
	fr_machine_t		*m;

	// deferred transitions?

	int			state;			//!< current state
	int			sequence;		//!< for tracking nested state transitions
	void			*uctx;			//!< user context used when running the state machine

	fr_machine_t		*parent;		//!< for running state machines inside of state machines
	fr_machine_t		*next;			//!< sibling
} fr_machine_ctx_t;

fr_machine_t *fr_machine_alloc(TALLOC_CTX *ctx, int max_states, int max_signal, fr_machine_edge_t const *edge, void *uctx);

int fr_machine_run(fr_machine_t *m, void *rctx);
int fr_machine_signal(fr_machine_t *m, void *rctx, int signal);
int fr_machine_transition(fr_machine_t *m, void *rctx, int state);

/*
  init

  thing is in state X

  thing moves to state Y
    exit state X
    enter state y
    run state y

  list of functions to call for state X

  API to add pre/post functions for state X
  API to delete pre / post functions for state X

*/
