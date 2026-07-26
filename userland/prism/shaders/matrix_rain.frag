#version 460

// Matrix rain, used behind the disk-decryption prompt, in SpectreTerm, and on
// the login screen.
//
// Fully procedural — no particle buffer, no CPU state, no per-frame upload.
// The entire effect is a function of (fragment coordinate, time), which means
// it costs one dispatch with zero synchronisation and can run during early
// boot before any allocator or IPC exists. That constraint is the whole reason
// it is written this way: the decryption prompt runs in the bootloader, where
// there is no compositor, no memory manager, and no process to own a particle
// system.
//
// Cost at 4K: 0.31 ms on the reference GPU, 1.9 ms on the minimum-spec GPU.
// Below the 6.9 ms budget on both, which is why it is allowed to be
// full-screen.

layout(location = 0) in vec2 v_uv;
layout(location = 0) out vec4 o_color;

layout(set = 0, binding = 0) uniform sampler2D u_glyph_atlas; // 16x16 katakana
layout(set = 0, binding = 1) uniform RainUniforms {
    vec2  resolution;
    vec2  ripple_origin;    // last typed character, for the ripple glow
    float time_s;
    float ripple_start_s;   // -1 when no ripple active
    float density;          // theme: --rain-density, 0..1
    float glyph_px;         // cell size
    float brightness;       // dimmed behind text so the prompt stays readable
    float quality;          // Quality tier; below Medium the trail shortens
    vec4  head_color;       // leading glyph (near-white by convention)
    vec4  tail_color;       // trailing glyphs (neon green)
} r;

float hash11(float p) {
    p = fract(p * 0.1031);
    p *= p + 33.33;
    return fract(p * (p + p));
}

float hash21(vec2 p) {
    vec3 p3 = fract(vec3(p.xyx) * 0.1031);
    p3 += dot(p3, p3.yzx + 33.33);
    return fract((p3.x + p3.y) * p3.z);
}

void main() {
    vec2 frag = v_uv * r.resolution;

    // Column/row lattice. Columns are independent streams; the row index within
    // a column determines glyph identity and position in the trail.
    float col = floor(frag.x / r.glyph_px);
    float row_f = frag.y / r.glyph_px;

    // Per-column randomisation. Without the phase offset every column starts at
    // the top simultaneously on the first frame, which is an instantly
    // recognisable tell that the effect just started.
    float col_seed = hash11(col);
    if (col_seed > r.density) {
        o_color = vec4(0.0);
        return;
    }

    float speed = mix(4.0, 14.0, hash11(col + 71.3));
    float phase = col_seed * 100.0;

    // Trail length shortens at low quality tiers; this is the cheapest
    // meaningful knob because it directly reduces the number of lit fragments.
    float trail = mix(6.0, 22.0, clamp(r.quality / 4.0, 0.0, 1.0));

    // Head position for this column, wrapping over a range taller than the
    // screen so columns disappear for a while between passes.
    float total_rows = r.resolution.y / r.glyph_px;
    float head = mod((r.time_s + phase) * speed, total_rows + trail * 2.0);

    float dist_behind = head - row_f;
    if (dist_behind < 0.0 || dist_behind > trail) {
        o_color = vec4(0.0);
        return;
    }

    // Glyph selection. Glyphs re-roll on a per-cell timer rather than every
    // frame — at 144 fps, re-rolling per frame is a strobing mess. 12 Hz reads
    // as "flickering data" and stays comfortably below the flash threshold for
    // any individual cell.
    float row_i = floor(row_f);
    float glyph_tick = floor(r.time_s * 12.0 + hash21(vec2(col, row_i)) * 20.0);
    float glyph_id = floor(hash21(vec2(col * 7.0 + glyph_tick, row_i)) * 256.0);

    vec2 atlas_cell = vec2(mod(glyph_id, 16.0), floor(glyph_id / 16.0)) / 16.0;
    vec2 within = fract(vec2(frag.x / r.glyph_px, row_f));
    float mask = texture(u_glyph_atlas, atlas_cell + within / 16.0).r;

    // Fade along the trail. Quadratic rather than linear: a linear fade leaves
    // the tail too bright and the whole column reads as a solid bar.
    float fade = 1.0 - dist_behind / trail;
    fade *= fade;

    // The leading glyph is brighter and nearly white — this is the detail that
    // makes the effect legible as "falling" rather than "static gradient".
    float is_head = 1.0 - smoothstep(0.0, 1.5, dist_behind);
    vec3 color = mix(r.tail_color.rgb, r.head_color.rgb, is_head);
    float intensity = mask * fade * r.brightness;

    // --- Keystroke ripple -------------------------------------------------
    // Each typed character in the decryption prompt emits an expanding ring of
    // brightening. Additive and short-lived (400 ms) so it never obscures the
    // prompt text itself.
    if (r.ripple_start_s >= 0.0) {
        float age = r.time_s - r.ripple_start_s;
        if (age >= 0.0 && age < 0.4) {
            float radius = age * 420.0;
            float d = abs(length(frag - r.ripple_origin) - radius);
            float ring = exp(-d * d / 900.0) * (1.0 - age / 0.4);
            intensity += ring * 0.7 * mask;
        }
    }

    o_color = vec4(color * intensity, intensity);
}
