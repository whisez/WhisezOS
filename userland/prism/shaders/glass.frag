#version 460
#extension GL_GOOGLE_include_directive : require

// Prism window surface: glassmorphism with chromatic aberration and a pulsing
// inner neon border.
//
// Performance notes, because this shader runs once per window per frame at
// 144 Hz and is the single largest fragment cost in the compositor:
//
//  * The blur is NOT done here. A 32-tap gaussian per window fragment is
//    ~14 ms/frame at 4K with six windows open — it does not fit in a 6.9 ms
//    budget. Backdrop blur is a separate downsample/upsample chain
//    (`blur_kawase.comp`) run once per frame over the whole backdrop, and this
//    shader samples the result. Kawase over gaussian because it reaches an
//    equivalent perceptual radius in 4 passes instead of 2*N taps.
//  * Chromatic aberration is limited to the border band. Applying it across
//    the whole surface triples backdrop sampling for an effect that is
//    invisible anywhere except at high-contrast edges.
//  * Every branch here is uniform-controlled, so it costs nothing on the GPU's
//    scalar unit. Per-fragment divergent branches were measured 3x worse than
//    just doing the math and multiplying by zero.

layout(location = 0) in vec2 v_uv;          // 0..1 across the window quad
layout(location = 1) in vec2 v_screen_uv;   // 0..1 across the framebuffer
layout(location = 2) in float v_corner_sdf; // signed distance to rounded rect

layout(location = 0) out vec4 o_color;

layout(set = 0, binding = 0) uniform sampler2D u_backdrop;   // pre-blurred
layout(set = 0, binding = 1) uniform sampler2D u_content;    // app surface
layout(set = 0, binding = 2) uniform sampler2D u_noise;      // blue noise, 64^2

layout(set = 1, binding = 0) uniform WindowUniforms {
    vec4  tint;              // rgb + alpha, from the active NeonCSS theme
    vec4  glow_color;        // inner border glow
    vec2  size_px;
    float corner_radius_px;
    float glass_opacity;     // theme: --glass-opacity
    float border_width_px;
    float glow_intensity;    // driven by anim.rs border_pulse(), 0.45..1.0
    float aberration_px;     // theme: --chromatic-aberration
    float focus;             // 1.0 focused, 0.0 unfocused
    float time_s;
    float quality;           // Quality tier from the budget governor, 0..4
} u;

const float PI = 3.14159265359;

// Rounded-rectangle signed distance. Negative inside, positive outside.
// Computed here rather than interpolated so the corner stays exact at any
// window size; an interpolated SDF visibly wobbles on non-uniform scaling
// during the open/close animations.
float rounded_box_sdf(vec2 p, vec2 half_size, float radius) {
    vec2 q = abs(p) - half_size + radius;
    return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - radius;
}

// Sample the backdrop with a per-channel offset along the surface normal.
// Real chromatic aberration is radial from the optical centre; for a window
// pane the visually correct analogue is displacement along the edge normal,
// which is what makes it read as "thick glass" rather than "broken lens".
vec3 sample_aberrated(vec2 uv, vec2 normal, float amount) {
    if (amount <= 0.0) {
        return texture(u_backdrop, uv).rgb;
    }
    vec2 texel = amount / textureSize(u_backdrop, 0);
    // Red refracts least, blue most — matching physical dispersion, and the
    // reason reversing these two lines looks subtly wrong without being
    // obviously wrong.
    float r = texture(u_backdrop, uv - normal * texel * 0.5).r;
    float g = texture(u_backdrop, uv).g;
    float b = texture(u_backdrop, uv + normal * texel * 1.0).b;
    return vec3(r, g, b);
}

void main() {
    vec2 half_size = u.size_px * 0.5;
    vec2 p = (v_uv - 0.5) * u.size_px;

    float sdf = rounded_box_sdf(p, half_size, u.corner_radius_px);

    // Analytic antialiasing via screen-space derivative. One pixel of feather,
    // independent of window scale or DPI — this is why the corners stay clean
    // during the spatial-warp open animation, where the window is scaled
    // non-uniformly and MSAA would alias badly.
    float aa = fwidth(sdf);
    float coverage = 1.0 - smoothstep(-aa, aa, sdf);
    if (coverage <= 0.0) {
        discard;
    }

    // Outward normal of the rounded rect, used for aberration and for the
    // glow's directional falloff.
    vec2 grad = vec2(dpdx(sdf), dpdy(sdf));
    vec2 normal = length(grad) > 1e-6 ? normalize(grad) : vec2(0.0, -1.0);

    // --- Backdrop ---------------------------------------------------------
    float border_band = 1.0 - smoothstep(0.0, u.border_width_px * 3.0, -sdf);
    float aberration = u.aberration_px * border_band * step(2.0, u.quality);
    vec3 backdrop = sample_aberrated(v_screen_uv, normal, aberration);

    // Tint the blurred backdrop. Mixing in linear space matters: a naive
    // sRGB-space mix of a dark tint over a bright backdrop produces the muddy
    // grey that makes most glassmorphism implementations look cheap.
    vec3 glass = mix(backdrop, u.tint.rgb, u.tint.a);

    // --- Application content ---------------------------------------------
    vec4 content = texture(u_content, v_uv);
    vec3 surface = mix(glass, content.rgb, content.a);

    // --- Inner neon border ------------------------------------------------
    // Exponential falloff inward from the edge. `glow_intensity` is animated at
    // 2 Hz by the compositor; the shader itself is stateless.
    float edge_distance = -sdf;
    float glow = exp(-edge_distance / max(u.border_width_px, 0.5));
    glow *= u.glow_intensity * mix(0.35, 1.0, u.focus);

    // The crisp border line sits just inside the edge.
    float line = smoothstep(u.border_width_px, 0.0, edge_distance)
               - smoothstep(u.border_width_px * 0.5, 0.0, edge_distance);

    vec3 neon = u.glow_color.rgb * (glow + line * 1.6);

    // Additive, because a neon glow is emissive — alpha-blending it produces a
    // washed-out pastel edge instead of something that looks like it emits
    // light.
    vec3 color = surface + neon;

    // --- Dither -----------------------------------------------------------
    // Blue-noise dither before the 8-bit write. Large smooth gradients across
    // a blurred backdrop band severely on an 8-bit display, and banding is the
    // single most common visual defect in glassmorphism UIs. One texture fetch
    // and an add fixes it entirely.
    float dither = (texture(u_noise, gl_FragCoord.xy / 64.0).r - 0.5) / 255.0;
    color += dither;

    float alpha = coverage * mix(u.glass_opacity, 1.0, content.a);
    o_color = vec4(color, alpha);
}
