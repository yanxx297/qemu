#ifndef SDL2_H
#define SDL2_H

struct sdl2_console {
    DisplayChangeListener dcl;
    DisplaySurface *surface;
    SDL_Texture *texture;
    SDL_Window *real_window;
    SDL_Renderer *real_renderer;
    int idx;
    int last_vm_running; /* per console for caption reasons */
    int x, y;
    int hidden;
};

void sdl2_window_create(struct sdl2_console *scon);
void sdl2_window_destroy(struct sdl2_console *scon);
void sdl2_window_resize(struct sdl2_console *scon);

void sdl2_reset_keys(struct sdl2_console *scon);
void sdl2_process_key(struct sdl2_console *scon,
                      SDL_KeyboardEvent *ev);

void sdl2_2d_update(DisplayChangeListener *dcl,
                    int x, int y, int w, int h);
void sdl2_2d_switch(DisplayChangeListener *dcl,
                    DisplaySurface *new_surface);

#endif /* SDL2_H */
