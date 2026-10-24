#ifndef SECRET_BOX_PROMPT_H
#define SECRET_BOX_PROMPT_H

enum {
	PROMPT_ALLOWED = 0,
	PROMPT_CANCELLED = 1,
	PROMPT_TIMEDOUT = 2,
	PROMPT_FAILED = 3,
	PROMPT_NO_WINDOW_SERVER = 4,
	PROMPT_NO_GLYPH = 5,
};

typedef struct {
	int verdict;
	long code;
} PromptResult;

PromptResult ShowTouchIDPrompt(const char *callerName, const char *iconPath,
                               const char *action, const char *subject,
                               const char *reason);

#endif
