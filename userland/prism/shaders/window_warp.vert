#version 460

// Window lifecycle geometry: spatial-warp open, particle-collapse close,
// origami minimise, and drag trail.
//
// All four run through one vertex shader with a uniform-selected mode. Four
// separate pipelines would mean four pipeline binds per frame during a window
// transition, and pipeline switches on tiled/deferred mobile GPUs (which the
// WhisezOS handheld target uses) cost more than the entire animation.
//
// The mesh is a 32x32 tessellated quad. That resolution is not arbitrary: the
// spatial warp displaces vertices along a radial curve, and below ~24
// subdivisions the curve visibly polygonises at the window's midpoint during
// the first 100 ms of the open animation.

layout(location = 0) in vec2 a_position;   // -0.5..0.5 quad space
layout(location = 1) in vec2 a_uv;

layout(location = 0) out vec2 v_uv;
layout(location = 1) out vec2 v_screen_uv;
layout(location = 2) out float v_corner_sdf;
layout(location = 3) out float v_particle_life;

layout(set = 1, binding = 1) uniform WarpUniforms {
    mat4  view_proj;
    vec4  window_rect;      // x, y, w, h in pixels
    vec2  singularity;      // origin point for open/close, screen px
    vec2  screen_size;
    float progress;         // 0..1, already eased by anim.rs
    float mode;             // 0=none 1=open 2=close 3=minimise 4=drag
    float depth_layer;      // parallax depth for the 3D desktop
    float time_s;
    vec2  taskbar_target;   // minimise destination, screen px
    vec2  drag_velocity;    // px/s, for trail stretch
} w;

const float MODE_OPEN     = 1.0;
const float MODE_CLOSE    = 2.0;
const float MODE_MINIMISE = 3.0;
const float MODE_DRAG     = 4.0;

const float PI = 3.14159265359;

float hash(vec2 p) {
    return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}

mat2 rot(float a) {
    float s = sin(a), c = cos(a);
    return mat2(c, -s, s, c);
}

// Spatial warp: the window emerges from a point, expanding faster along its
// major axis so it reads as "unfolding into existence" rather than "scaling
// up". A uniform scale is the obvious implementation and looks like every
// other OS; the anisotropy is what makes it feel spatial.
vec2 warp_open(vec2 pos, float t) {
    float radial = length(pos) * 2.0;

    // Vertices further from centre arrive later, producing a leading edge.
    float local_t = clamp((t - radial * 0.18) / 0.82, 0.0, 1.0);

    // Slight rotational shear that unwinds as it settles.
    float twist = (1.0 - local_t) * 0.55 * sign(pos.x + 0.001);
    vec2 twisted = rot(twist) * pos;

    vec2 anisotropic = vec2(local_t, pow(local_t, 1.35));
    return twisted * anisotropic;
}

// Close: each vertex becomes a particle with an outward velocity plus gravity.
// The fragment shader fades on `v_particle_life`.
vec2 warp_close(vec2 pos, float t, out float life) {
    float seed = hash(a_uv * 64.0);

    vec2 dir = normalize(pos + vec2(seed - 0.5, seed * 0.7 - 0.35) * 0.4);
    float speed = mix(0.6, 1.8, seed);

    // Staggered start: particles do not all launch on the same frame, which is
    // what separates an explosion from a balloon popping.
    float local_t = clamp((t - seed * 0.25) / 0.75, 0.0, 1.0);

    vec2 displaced = pos + dir * speed * local_t;
    displaced.y -= 0.9 * local_t * local_t;   // gravity

    life = 1.0 - local_t;
    return displaced;
}

// Minimise: fold along alternating horizontal creases (origami), then fly the
// folded strip to the taskbar slot along a quadratic bezier so it arcs rather
// than travelling in a straight line.
vec2 warp_minimise(vec2 pos, float t) {
    float fold_t = clamp(t / 0.45, 0.0, 1.0);
    float fly_t  = clamp((t - 0.4) / 0.6, 0.0, 1.0);

    // Six creases; alternate direction per band gives the accordion.
    const float BANDS = 6.0;
    float band = floor((pos.y + 0.5) * BANDS);
    float within = fract((pos.y + 0.5) * BANDS) - 0.5;
    float dir = mod(band, 2.0) * 2.0 - 1.0;

    vec2 folded = pos;
    folded.y = (band + 0.5) / BANDS - 0.5 + within * (1.0 - fold_t * 0.92);
    folded.x *= 1.0 - fold_t * 0.35;
    folded.x += dir * within * fold_t * 0.22;

    // Fly to the taskbar. Control point offset upward so it arcs.
    vec2 start_px = w.window_rect.xy + w.window_rect.zw * 0.5;
    vec2 ctrl_px  = mix(start_px, w.taskbar_target, 0.5) + vec2(0.0, -160.0);

    vec2 a = mix(start_px, ctrl_px, fly_t);
    vec2 b = mix(ctrl_px, w.taskbar_target, fly_t);
    vec2 centre_px = mix(a, b, fly_t);

    vec2 scale = mix(w.window_rect.zw, vec2(48.0), fly_t);
    return (centre_px + folded * scale - w.window_rect.xy) / w.window_rect.zw - 0.5;
}

// Drag: stretch the trailing edge along the negative velocity vector. The
// stretch is clamped because an unbounded stretch on a fast flick produces a
// window smeared across the entire screen, which reads as a glitch.
vec2 warp_drag(vec2 pos) {
    float speed = length(w.drag_velocity);
    if (speed < 1.0) {
        return pos;
    }
    vec2 dir = w.drag_velocity / speed;
    float stretch = min(speed / 4000.0, 0.22);

    // Only vertices on the trailing half stretch.
    float trailing = max(0.0, -dot(normalize(pos + 1e-6), dir));
    return pos - dir * stretch * trailing;
}

void main() {
    vec2 pos = a_position;
    float life = 1.0;

    if (w.mode == MODE_OPEN) {
        pos = warp_open(pos, w.progress);
    } else if (w.mode == MODE_CLOSE) {
        pos = warp_close(pos, w.progress, life);
    } else if (w.mode == MODE_MINIMISE) {
        pos = warp_minimise(pos, w.progress);
    } else if (w.mode == MODE_DRAG) {
        pos = warp_drag(pos);
    }

    vec2 pixel = w.window_rect.xy + (pos + 0.5) * w.window_rect.zw;

    // Open/close originate from the singularity point rather than the window
    // centre, so a window opened from a taskbar icon grows out of that icon.
    if (w.mode == MODE_OPEN || w.mode == MODE_CLOSE) {
        float pull = (w.mode == MODE_OPEN) ? (1.0 - w.progress) : w.progress;
        pixel = mix(pixel, w.singularity, pull * pull * 0.85);
    }

    v_uv = a_uv;
    v_screen_uv = pixel / w.screen_size;
    v_particle_life = life;

    // Parallax depth: layers further back translate less with the virtual
    // camera. Written to Z so the compositor's depth test resolves overlap
    // without a CPU-side sort.
    float z = w.depth_layer * 0.001;
    gl_Position = w.view_proj * vec4(pixel, z, 1.0);

    // The fragment shader needs an SDF that survives the warp; recompute from
    // the *unwarped* position so corners stay round while the mesh deforms.
    vec2 half_px = w.window_rect.zw * 0.5;
    vec2 q = abs(a_position * w.window_rect.zw) - half_px + 12.0;
    v_corner_sdf = length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - 12.0;
}
