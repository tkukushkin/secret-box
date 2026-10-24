#import "prompt.h"

#import <Cocoa/Cocoa.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <LocalAuthenticationEmbeddedUI/LocalAuthenticationEmbeddedUI.h>
#import <stdatomic.h>
#import <stdlib.h>

#define WIDTH 400.0
#define BASE_HEIGHT 300.0
#define PAD 24.0
#define LOGO 64.0
#define BODY_SIZE 15.0
#define BUTTON_W 84.0
#define BUTTON_H 28.0
#define BASE_ROW_TOP 250.0
#define GLYPH 32.0
#define HINT_W 220.0
#define HINT_GAP 10.0
#define SUBJECT_TOP 166.0
#define SUBJECT_H 36.0
#define SUBJECT_SIZE 28.0
#define SUBJECT_LIST_SIZE 17.0

// Window height and button-row offset; both grow by however much the subject
// label exceeds SUBJECT_H.
static double windowHeight = BASE_HEIGHT;
static double rowTop = BASE_ROW_TOP;

// LAError codes meaning the evaluation was cancelled rather than failed:
// userCancel (-2), systemCancel (-4), appCancel (-9).
static BOOL IsCancelCode(long code) {
	return code == -2 || code == -4 || code == -9;
}

// Completion-block state of one evaluatePolicy call; the reply runs on a
// private queue. Heap-allocated and intentionally leaked so a late reply after
// a timeout cannot write to freed memory.
typedef struct {
	atomic_bool done;
	atomic_bool success;
	atomic_long code;
} EvalState;

// AppKit's origin is bottom-left; place a rect by its distance from the top.
static NSRect FromTop(double x, double top, double w, double h) {
	return NSMakeRect(x, windowHeight - top - h, w, h);
}

static NSRect FullRow(double top, double h) {
	return FromTop(PAD, top, WIDTH - 2.0 * PAD, h);
}

static NSFont *SysFont(double size, BOOL bold) {
	return [NSFont systemFontOfSize:size weight:(bold ? NSFontWeightBold : NSFontWeightRegular)];
}

static NSTextField *PlainLabel(NSRect frame) {
	NSTextField *field = [[NSTextField alloc] initWithFrame:frame];
	field.bezeled = NO;
	field.drawsBackground = NO;
	field.editable = NO;
	field.selectable = NO;
	return field;
}

static NSTextField *CenteredLabel(NSString *text, NSFont *font, NSColor *color, NSRect frame) {
	NSTextField *field = PlainLabel(frame);
	field.stringValue = text;
	field.font = font;
	field.textColor = color;
	field.alignment = NSTextAlignmentCenter;
	field.maximumNumberOfLines = 1;
	field.lineBreakMode = NSLineBreakByTruncatingMiddle;
	return field;
}

// Subject label sized to its text: a single name that fits stays on one large
// line; several names (one per line) or a name too wide for it wrap in full at
// a smaller size. Only the frame's size is set; the caller places it.
static NSTextField *SubjectLabel(NSString *text) {
	double width = WIDTH - 2.0 * PAD;
	NSColor *primary = [NSColor labelColor];
	NSTextField *large = CenteredLabel(text, SysFont(SUBJECT_SIZE, YES), primary, NSMakeRect(0.0, 0.0, width, SUBJECT_H));
	if ([text rangeOfString:@"\n"].location == NSNotFound &&
	    [large.cell cellSizeForBounds:NSMakeRect(0.0, 0.0, CGFLOAT_MAX, SUBJECT_H)].width <= width) {
		return large;
	}
	NSTextField *field = PlainLabel(NSMakeRect(0.0, 0.0, width, SUBJECT_H));
	field.stringValue = text;
	field.font = SysFont(SUBJECT_LIST_SIZE, YES);
	field.textColor = primary;
	field.alignment = NSTextAlignmentCenter;
	field.usesSingleLineMode = NO;
	field.maximumNumberOfLines = 0;
	field.lineBreakMode = NSLineBreakByWordWrapping;
	field.cell.wraps = YES;
	field.cell.scrollable = NO;
	field.preferredMaxLayoutWidth = width;
	double height = ceil([field.cell cellSizeForBounds:NSMakeRect(0.0, 0.0, width, CGFLOAT_MAX)].height);
	field.frame = NSMakeRect(0.0, 0.0, width, MAX(SUBJECT_H, height));
	return field;
}

static NSTextField *HintLabel(NSRect frame) {
	NSString *prefix = @"Confirm with ";
	NSString *accent = @"Touch ID";
	NSString *full = [prefix stringByAppendingString:accent];
	NSMutableAttributedString *attr = [[NSMutableAttributedString alloc] initWithString:full];
	NSMutableParagraphStyle *para = [[NSMutableParagraphStyle alloc] init];
	para.alignment = NSTextAlignmentRight;
	NSRange whole = NSMakeRange(0, full.length);
	[attr addAttribute:NSFontAttributeName value:SysFont(BODY_SIZE, NO) range:whole];
	[attr addAttribute:NSForegroundColorAttributeName value:[NSColor labelColor] range:whole];
	[attr addAttribute:NSParagraphStyleAttributeName value:para range:whole];
	[attr addAttribute:NSFontAttributeName value:SysFont(BODY_SIZE, YES) range:NSMakeRange(prefix.length, accent.length)];
	NSTextField *field = PlainLabel(frame);
	field.attributedStringValue = attr;
	field.maximumNumberOfLines = 1;
	return field;
}

static NSImageView *IconView(const char *iconPath) {
	NSString *path = iconPath ? [NSString stringWithUTF8String:iconPath] : @"";
	if (path.length == 0 || ![[NSFileManager defaultManager] fileExistsAtPath:path]) {
		return nil;
	}
	NSImage *image = [[NSWorkspace sharedWorkspace] iconForFile:path];
	NSImageView *view = [NSImageView imageViewWithImage:image];
	view.imageScaling = NSImageScaleProportionallyUpOrDown;
	view.frame = FromTop((WIDTH - LOGO) / 2.0, 34.0, LOGO, LOGO);
	return view;
}

static NSView *GlyphView(LAContext *context) {
	NSView *view = [[LAAuthenticationView alloc] initWithContext:context controlSize:NSControlSizeSmall];
	if (view == nil) {
		return nil;
	}
	view.frame = FromTop(WIDTH - PAD - GLYPH, rowTop - 1.0, GLYPH, GLYPH);
	return view;
}

static NSWindow *BareWindow(void) {
	NSWindowStyleMask style = NSWindowStyleMaskTitled | NSWindowStyleMaskFullSizeContentView | NSWindowStyleMaskClosable;
	NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0.0, 0.0, WIDTH, windowHeight)
	                                               styleMask:style
	                                                 backing:NSBackingStoreBuffered
	                                                   defer:NO];
	// performClose: from the cancel button would otherwise free the window under us.
	window.releasedWhenClosed = NO;
	window.titleVisibility = NSWindowTitleHidden;
	window.titlebarAppearsTransparent = YES;
	window.movableByWindowBackground = YES;
	window.level = NSModalPanelWindowLevel;
	window.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces | NSWindowCollectionBehaviorFullScreenAuxiliary;
	NSWindowButton buttons[] = {NSWindowCloseButton, NSWindowMiniaturizeButton, NSWindowZoomButton};
	for (int i = 0; i < 3; i++) {
		[[window standardWindowButton:buttons[i]] setHidden:YES];
	}
	[window center];
	return window;
}

static void AddHero(NSView *content, const char *callerName, const char *action, NSTextField *subject) {
	NSColor *secondary = [NSColor secondaryLabelColor];
	NSString *name = [NSString stringWithUTF8String:callerName];
	[content addSubview:CenteredLabel(name, SysFont(15.0, YES), secondary, FullRow(112.0, 20.0))];
	[content addSubview:CenteredLabel([NSString stringWithUTF8String:action], SysFont(14.0, NO), secondary, FullRow(136.0, 20.0))];
	subject.frame = FullRow(SUBJECT_TOP, subject.frame.size.height);
	[content addSubview:subject];
}

static NSButton *CancelButton(NSWindow *window) {
	NSButton *cancel = [NSButton buttonWithTitle:@"Cancel" target:window action:@selector(performClose:)];
	cancel.controlSize = NSControlSizeLarge;
	cancel.font = SysFont(BODY_SIZE, NO);
	cancel.keyEquivalent = @"\033";
	cancel.frame = FromTop(PAD, rowTop, BUTTON_W, BUTTON_H);
	return cancel;
}

static void PumpEvents(NSApplication *app, double seconds) {
	@autoreleasepool {
		NSDate *until = [NSDate dateWithTimeIntervalSinceNow:seconds];
		NSEvent *event = [app nextEventMatchingMask:NSEventMaskAny untilDate:until inMode:NSDefaultRunLoopMode dequeue:YES];
		if (event != nil) {
			[app sendEvent:event];
			[app updateWindows];
		}
	}
}

PromptResult ShowTouchIDPrompt(const char *callerName, const char *iconPath,
                               const char *action, const char *subject,
                               const char *reason) {
	PromptResult result = {PROMPT_FAILED, 0};

	CFDictionaryRef session = CGSessionCopyCurrentDictionary();
	if (session == NULL) {
		result.verdict = PROMPT_NO_WINDOW_SERVER;
		return result;
	}
	CFRelease(session);

	NSTextField *subjectLabel = SubjectLabel([NSString stringWithUTF8String:subject]);
	double extra = subjectLabel.frame.size.height - SUBJECT_H;
	windowHeight = BASE_HEIGHT + extra;
	rowTop = BASE_ROW_TOP + extra;

	LAContext *context = [[LAContext alloc] init];
	NSView *glyph = GlyphView(context);
	if (glyph == nil) {
		result.verdict = PROMPT_NO_GLYPH;
		return result;
	}

	NSApplication *app = [NSApplication sharedApplication];
	[app setActivationPolicy:NSApplicationActivationPolicyAccessory];
	[app finishLaunching];

	NSWindow *window = BareWindow();
	NSView *content = window.contentView;
	NSImageView *icon = IconView(iconPath);
	if (icon != nil) {
		[content addSubview:icon];
	}
	AddHero(content, callerName, action, subjectLabel);
	[content addSubview:CancelButton(window)];
	[content addSubview:glyph];
	[content addSubview:HintLabel(FromTop(WIDTH - PAD - GLYPH - HINT_GAP - HINT_W, rowTop + 3.0, HINT_W, 22.0))];

	[window makeKeyAndOrderFront:nil];
	// Takes focus from the frontmost app.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	[app activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop

	EvalState *st = calloc(1, sizeof(EvalState));
	[context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
	        localizedReason:[NSString stringWithUTF8String:reason]
	                  reply:^(BOOL success, NSError *error) {
		atomic_store(&st->success, success);
		if (error != nil) {
			atomic_store(&st->code, (long)error.code);
		}
		atomic_store(&st->done, true);
	}];

	NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:60.0];
	BOOL invalidated = NO;
	while (!atomic_load(&st->done) && [deadline timeIntervalSinceNow] > 0.0) {
		PumpEvents(app, 0.02);
		// Cancel/Esc close the window; invalidating fires the reply with a cancel code.
		if (!invalidated && !window.isVisible) {
			[context invalidate];
			invalidated = YES;
		}
	}

	if (!atomic_load(&st->done)) {
		[context invalidate];
		result.verdict = PROMPT_TIMEDOUT;
	} else if (atomic_load(&st->success)) {
		result.verdict = PROMPT_ALLOWED;
	} else {
		long code = atomic_load(&st->code);
		result.verdict = IsCancelCode(code) ? PROMPT_CANCELLED : PROMPT_FAILED;
		result.code = code;
	}

	[window orderOut:nil];
	PumpEvents(app, 0.02);
	return result;
}
