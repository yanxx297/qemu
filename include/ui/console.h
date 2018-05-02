#ifndef CONSOLE_H
#define CONSOLE_H

#include "ui/qemu-pixman.h"
#include "qom/object.h"
#include "qapi/qmp/qdict.h"
#include "qemu/notify.h"
#include "monitor/monitor.h"
#include "qapi-types.h"
#include "qapi/error.h"

/* keyboard/mouse support */

#define MOUSE_EVENT_LBUTTON 0x01
#define MOUSE_EVENT_RBUTTON 0x02
#define MOUSE_EVENT_MBUTTON 0x04
#define MOUSE_EVENT_WHEELUP 0x08
#define MOUSE_EVENT_WHEELDN 0x10

/* identical to the ps/2 keyboard bits */
#define QEMU_SCROLL_LOCK_LED (1 << 0)
#define QEMU_NUM_LOCK_LED    (1 << 1)
#define QEMU_CAPS_LOCK_LED   (1 << 2)

/* in ms */
#define GUI_REFRESH_INTERVAL_DEFAULT    30
#define GUI_REFRESH_INTERVAL_IDLE     3000

typedef void QEMUPutKBDEvent(void *opaque, int keycode);
typedef void QEMUPutLEDEvent(void *opaque, int ledstate);
typedef void QEMUPutMouseEvent(void *opaque, int dx, int dy, int dz, int buttons_state);

typedef struct QEMUPutMouseEntry QEMUPutMouseEntry;
typedef struct QEMUPutKbdEntry QEMUPutKbdEntry;
typedef struct QEMUPutLEDEntry QEMUPutLEDEntry;

QEMUPutKbdEntry *qemu_add_kbd_event_handler(QEMUPutKBDEvent *func,
                                            void *opaque);
void qemu_remove_kbd_event_handler(QEMUPutKbdEntry *entry);
QEMUPutMouseEntry *qemu_add_mouse_event_handler(QEMUPutMouseEvent *func,
                                                void *opaque, int absolute,
                                                const char *name);
void qemu_remove_mouse_event_handler(QEMUPutMouseEntry *entry);
void qemu_activate_mouse_event_handler(QEMUPutMouseEntry *entry);

QEMUPutLEDEntry *qemu_add_led_event_handler(QEMUPutLEDEvent *func, void *opaque);
void qemu_remove_led_event_handler(QEMUPutLEDEntry *entry);

void kbd_put_ledstate(int ledstate);

struct MouseTransformInfo {
    /* Touchscreen resolution */
    int x;
    int y;
    /* Calibration values as used/generated by tslib */
    int a[7];
};

void do_mouse_set(Monitor *mon, const QDict *qdict);

/* keysym is a unicode code except for special keys (see QEMU_KEY_xxx
   constants) */
#define QEMU_KEY_ESC1(c) ((c) | 0xe100)
#define QEMU_KEY_BACKSPACE  0x007f
#define QEMU_KEY_UP         QEMU_KEY_ESC1('A')
#define QEMU_KEY_DOWN       QEMU_KEY_ESC1('B')
#define QEMU_KEY_RIGHT      QEMU_KEY_ESC1('C')
#define QEMU_KEY_LEFT       QEMU_KEY_ESC1('D')
#define QEMU_KEY_HOME       QEMU_KEY_ESC1(1)
#define QEMU_KEY_END        QEMU_KEY_ESC1(4)
#define QEMU_KEY_PAGEUP     QEMU_KEY_ESC1(5)
#define QEMU_KEY_PAGEDOWN   QEMU_KEY_ESC1(6)
#define QEMU_KEY_DELETE     QEMU_KEY_ESC1(3)

#define QEMU_KEY_CTRL_UP         0xe400
#define QEMU_KEY_CTRL_DOWN       0xe401
#define QEMU_KEY_CTRL_LEFT       0xe402
#define QEMU_KEY_CTRL_RIGHT      0xe403
#define QEMU_KEY_CTRL_HOME       0xe404
#define QEMU_KEY_CTRL_END        0xe405
#define QEMU_KEY_CTRL_PAGEUP     0xe406
#define QEMU_KEY_CTRL_PAGEDOWN   0xe407

void kbd_put_keysym(int keysym);

/* consoles */

#define TYPE_QEMU_CONSOLE "qemu-console"
#define QEMU_CONSOLE(obj) \
    OBJECT_CHECK(QemuConsole, (obj), TYPE_QEMU_CONSOLE)
#define QEMU_CONSOLE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(QemuConsoleClass, (obj), TYPE_QEMU_CONSOLE)
#define QEMU_CONSOLE_CLASS(klass) \
    OBJECT_CLASS_CHECK(QemuConsoleClass, (klass), TYPE_QEMU_CONSOLE)

typedef struct QemuConsoleClass QemuConsoleClass;

struct QemuConsoleClass {
    ObjectClass parent_class;
};

#define QEMU_BIG_ENDIAN_FLAG    0x01
#define QEMU_ALLOCATED_FLAG     0x02

struct PixelFormat {
    uint8_t bits_per_pixel;
    uint8_t bytes_per_pixel;
    uint8_t depth; /* color depth in bits */
    uint32_t rmask, gmask, bmask, amask;
    uint8_t rshift, gshift, bshift, ashift;
    uint8_t rmax, gmax, bmax, amax;
    uint8_t rbits, gbits, bbits, abits;
};

struct DisplaySurface {
    pixman_format_code_t format;
    pixman_image_t *image;
    uint8_t flags;

    struct PixelFormat pf;
};

typedef struct QemuUIInfo {
    /* geometry */
    int       xoff;
    int       yoff;
    uint32_t  width;
    uint32_t  height;
} QemuUIInfo;

/* cursor data format is 32bit RGBA */
typedef struct QEMUCursor {
    int                 width, height;
    int                 hot_x, hot_y;
    int                 refcount;
    uint32_t            data[];
} QEMUCursor;

QEMUCursor *cursor_alloc(int width, int height);
void cursor_get(QEMUCursor *c);
void cursor_put(QEMUCursor *c);
QEMUCursor *cursor_builtin_hidden(void);
QEMUCursor *cursor_builtin_left_ptr(void);
void cursor_print_ascii_art(QEMUCursor *c, const char *prefix);
int cursor_get_mono_bpl(QEMUCursor *c);
void cursor_set_mono(QEMUCursor *c,
                     uint32_t foreground, uint32_t background, uint8_t *image,
                     int transparent, uint8_t *mask);
void cursor_get_mono_image(QEMUCursor *c, int foreground, uint8_t *mask);
void cursor_get_mono_mask(QEMUCursor *c, int transparent, uint8_t *mask);

typedef struct DisplayChangeListenerOps {
    const char *dpy_name;

    void (*dpy_refresh)(DisplayChangeListener *dcl);

    void (*dpy_gfx_update)(DisplayChangeListener *dcl,
                           int x, int y, int w, int h);
    void (*dpy_gfx_switch)(DisplayChangeListener *dcl,
                           struct DisplaySurface *new_surface);
    void (*dpy_gfx_copy)(DisplayChangeListener *dcl,
                         int src_x, int src_y,
                         int dst_x, int dst_y, int w, int h);

    void (*dpy_text_cursor)(DisplayChangeListener *dcl,
                            int x, int y);
    void (*dpy_text_resize)(DisplayChangeListener *dcl,
                            int w, int h);
    void (*dpy_text_update)(DisplayChangeListener *dcl,
                            int x, int y, int w, int h);

    void (*dpy_mouse_set)(DisplayChangeListener *dcl,
                          int x, int y, int on);
    void (*dpy_cursor_define)(DisplayChangeListener *dcl,
                              QEMUCursor *cursor);
} DisplayChangeListenerOps;

struct DisplayChangeListener {
    uint64_t update_interval;
    const DisplayChangeListenerOps *ops;
    DisplayState *ds;
    QemuConsole *con;

    QLIST_ENTRY(DisplayChangeListener) next;
};

DisplayState *init_displaystate(void);
DisplaySurface* qemu_create_displaysurface_from(int width, int height, int bpp,
                                                int linesize, uint8_t *data,
                                                bool byteswap);
PixelFormat qemu_different_endianness_pixelformat(int bpp);
PixelFormat qemu_default_pixelformat(int bpp);

DisplaySurface *qemu_create_displaysurface(int width, int height);
void qemu_free_displaysurface(DisplaySurface *surface);

static inline int is_surface_bgr(DisplaySurface *surface)
{
    if (surface->pf.bits_per_pixel == 32 && surface->pf.rshift == 0)
        return 1;
    else
        return 0;
}

static inline int is_buffer_shared(DisplaySurface *surface)
{
    return !(surface->flags & QEMU_ALLOCATED_FLAG);
}

void register_displaychangelistener(DisplayChangeListener *dcl);
void update_displaychangelistener(DisplayChangeListener *dcl,
                                  uint64_t interval);
void unregister_displaychangelistener(DisplayChangeListener *dcl);

int dpy_set_ui_info(QemuConsole *con, QemuUIInfo *info);

void dpy_gfx_update(QemuConsole *con, int x, int y, int w, int h);
void dpy_gfx_replace_surface(QemuConsole *con,
                             DisplaySurface *surface);
void dpy_gfx_copy(QemuConsole *con, int src_x, int src_y,
                  int dst_x, int dst_y, int w, int h);
void dpy_text_cursor(QemuConsole *con, int x, int y);
void dpy_text_update(QemuConsole *con, int x, int y, int w, int h);
void dpy_text_resize(QemuConsole *con, int w, int h);
void dpy_mouse_set(QemuConsole *con, int x, int y, int on);
void dpy_cursor_define(QemuConsole *con, QEMUCursor *cursor);
bool dpy_cursor_define_supported(QemuConsole *con);

static inline int surface_stride(DisplaySurface *s)
{
    return pixman_image_get_stride(s->image);
}

static inline void *surface_data(DisplaySurface *s)
{
    return pixman_image_get_data(s->image);
}

static inline int surface_width(DisplaySurface *s)
{
    return pixman_image_get_width(s->image);
}

static inline int surface_height(DisplaySurface *s)
{
    return pixman_image_get_height(s->image);
}

static inline int surface_bits_per_pixel(DisplaySurface *s)
{
    int bits = PIXMAN_FORMAT_BPP(s->format);
    return bits;
}

static inline int surface_bytes_per_pixel(DisplaySurface *s)
{
    int bits = PIXMAN_FORMAT_BPP(s->format);
    return (bits + 7) / 8;
}

#ifdef CONFIG_CURSES
#include <curses.h>
typedef chtype console_ch_t;
#else
typedef unsigned long console_ch_t;
#endif
static inline void console_write_ch(console_ch_t *dest, uint32_t ch)
{
    if (!(ch & 0xff))
        ch |= ' ';
    *dest = ch;
}

typedef struct GraphicHwOps {
    void (*invalidate)(void *opaque);
    void (*gfx_update)(void *opaque);
    void (*text_update)(void *opaque, console_ch_t *text);
    void (*update_interval)(void *opaque, uint64_t interval);
    int (*ui_info)(void *opaque, uint32_t head, QemuUIInfo *info);
} GraphicHwOps;

QemuConsole *graphic_console_init(DeviceState *dev, uint32_t head,
                                  const GraphicHwOps *ops,
                                  void *opaque);

void graphic_hw_update(QemuConsole *con);
void graphic_hw_invalidate(QemuConsole *con);
void graphic_hw_text_update(QemuConsole *con, console_ch_t *chardata);

QemuConsole *qemu_console_lookup_by_index(unsigned int index);
QemuConsole *qemu_console_lookup_by_device(DeviceState *dev, uint32_t head);
bool qemu_console_is_visible(QemuConsole *con);
bool qemu_console_is_graphic(QemuConsole *con);
bool qemu_console_is_fixedsize(QemuConsole *con);
int qemu_console_get_index(QemuConsole *con);
uint32_t qemu_console_get_head(QemuConsole *con);
QemuUIInfo *qemu_console_get_ui_info(QemuConsole *con);
int qemu_console_get_width(QemuConsole *con, int fallback);
int qemu_console_get_height(QemuConsole *con, int fallback);

void text_consoles_set_display(DisplayState *ds);
void console_select(unsigned int index);
void console_color_init(DisplayState *ds);
void qemu_console_resize(QemuConsole *con, int width, int height);
void qemu_console_copy(QemuConsole *con, int src_x, int src_y,
                       int dst_x, int dst_y, int w, int h);
DisplaySurface *qemu_console_surface(QemuConsole *con);
DisplayState *qemu_console_displaystate(QemuConsole *console);

typedef CharDriverState *(VcHandler)(ChardevVC *vc);

CharDriverState *vc_init(ChardevVC *vc);
void register_vc_handler(VcHandler *handler);

/* sdl.c */
void sdl_display_init(DisplayState *ds, int full_screen, int no_frame);

/* cocoa.m */
void cocoa_display_init(DisplayState *ds, int full_screen);

/* vnc.c */
void vnc_display_init(DisplayState *ds);
void vnc_display_open(DisplayState *ds, const char *display, Error **errp);
void vnc_display_add_client(DisplayState *ds, int csock, bool skipauth);
char *vnc_display_local_addr(DisplayState *ds);
#ifdef CONFIG_VNC
int vnc_display_password(DisplayState *ds, const char *password);
int vnc_display_pw_expire(DisplayState *ds, time_t expires);
#else
static inline int vnc_display_password(DisplayState *ds, const char *password)
{
    return -ENODEV;
}
static inline int vnc_display_pw_expire(DisplayState *ds, time_t expires)
{
    return -ENODEV;
};
#endif

/* curses.c */
void curses_display_init(DisplayState *ds, int full_screen);

/* input.c */
int index_from_key(const char *key);

/* gtk.c */
void early_gtk_display_init(void);
void gtk_display_init(DisplayState *ds, bool full_screen);

#endif
