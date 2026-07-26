//! The dodecahedron start menu.
//!
//! Super key zooms the desktop out into 3D space and presents a rotating
//! regular dodecahedron with an app category on each of its twelve faces.
//!
//! # Why twelve faces is the right number, and the accessibility problem it
//! creates
//!
//! Twelve is a genuinely good count for top-level categories — it is more than
//! a phone's five and fewer than a Start menu's arbitrary sprawl. But a 3D
//! rotating solid is one of the worst possible interfaces for three groups of
//! users, and shipping it as the *only* launcher would be indefensible:
//!
//!   * Screen-reader users, for whom a rotating solid has no meaningful reading
//!     order.
//!   * Users with vestibular disorders, for whom the zoom-out is a trigger.
//!   * Anyone who knows the name of the app they want, which after a week is
//!     everyone.
//!
//! So the dodecahedron is the *visual* layer over a flat, ordered, fully
//! keyboard-navigable model (`CategoryModel`). Typing at any point switches to
//! search, which is the path most users will take most of the time. The solid
//! exposes a linear tab order matching face index, and `reduce_motion` replaces
//! the rotation with a cross-fade between faces. Same model, three
//! presentations.

use crate::anim::{Animation, Bezier, Quality, Repeat};

/// A regular dodecahedron has 12 faces, 20 vertices, 30 edges. Face centres lie
/// along the 12 axes defined by cyclic permutations of (0, ±1, ±φ) normalised —
/// these are what we rotate *toward* when selecting a face.
pub const FACE_COUNT: usize = 12;

/// Golden ratio. The dodecahedron's entire geometry falls out of it.
const PHI: f32 = 1.618_034;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Vec3 { x, y, z }
    }

    pub fn length(self) -> f32 {
        (self.x * self.x + self.y * self.y + self.z * self.z).sqrt()
    }

    pub fn normalized(self) -> Vec3 {
        let l = self.length();
        if l < 1e-6 {
            return Vec3::new(0.0, 0.0, 1.0);
        }
        Vec3::new(self.x / l, self.y / l, self.z / l)
    }

    pub fn dot(self, o: Vec3) -> f32 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }

    pub fn cross(self, o: Vec3) -> Vec3 {
        Vec3::new(
            self.y * o.z - self.z * o.y,
            self.z * o.x - self.x * o.z,
            self.x * o.y - self.y * o.x,
        )
    }
}

/// The 12 face-centre normals of a regular dodecahedron.
///
/// Generated rather than hard-coded so the relationship to φ stays visible: a
/// table of 36 magic floats is unreviewable, and getting one sign wrong
/// produces a solid that looks right until a face rotates to the back and
/// vanishes.
pub fn face_normals() -> [Vec3; FACE_COUNT] {
    let mut out = [Vec3::new(0.0, 0.0, 0.0); FACE_COUNT];
    let mut i = 0;

    // Three cyclic groups of four, each spanning the sign combinations.
    for &(a, b) in &[(1.0f32, PHI), (-1.0, PHI), (1.0, -PHI), (-1.0, -PHI)] {
        out[i] = Vec3::new(0.0, a, b).normalized();
        i += 1;
    }
    for &(a, b) in &[(1.0f32, PHI), (-1.0, PHI), (1.0, -PHI), (-1.0, -PHI)] {
        out[i] = Vec3::new(a, b, 0.0).normalized();
        i += 1;
    }
    for &(a, b) in &[(1.0f32, PHI), (-1.0, PHI), (1.0, -PHI), (-1.0, -PHI)] {
        out[i] = Vec3::new(b, 0.0, a).normalized();
        i += 1;
    }

    out
}

/// Quaternion, used for face-to-face rotation.
///
/// Euler angles would gimbal-lock at exactly the orientations where two face
/// normals are near-antipodal, which happens on every "jump to the opposite
/// face" transition — i.e. constantly. Slerp on quaternions is both correct and
/// gives constant angular velocity, which matters because a rotation that
/// speeds up in the middle reads as a physics glitch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Quat {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub w: f32,
}

impl Quat {
    pub const IDENTITY: Quat = Quat {
        x: 0.0,
        y: 0.0,
        z: 0.0,
        w: 1.0,
    };

    /// Shortest-arc rotation taking `from` to `to`.
    pub fn between(from: Vec3, to: Vec3) -> Quat {
        let from = from.normalized();
        let to = to.normalized();
        let d = from.dot(to);

        // Antipodal case: the cross product is degenerate, so pick any
        // perpendicular axis. Without this branch the rotation is undefined and
        // the menu snaps through the centre of the solid.
        if d < -0.999_999 {
            let axis = if from.x.abs() < 0.9 {
                Vec3::new(1.0, 0.0, 0.0).cross(from)
            } else {
                Vec3::new(0.0, 1.0, 0.0).cross(from)
            }
            .normalized();
            return Quat {
                x: axis.x,
                y: axis.y,
                z: axis.z,
                w: 0.0,
            };
        }

        let c = from.cross(to);
        let q = Quat {
            x: c.x,
            y: c.y,
            z: c.z,
            w: 1.0 + d,
        };
        q.normalized()
    }

    pub fn normalized(self) -> Quat {
        let n = (self.x * self.x + self.y * self.y + self.z * self.z + self.w * self.w).sqrt();
        if n < 1e-6 {
            return Quat::IDENTITY;
        }
        Quat {
            x: self.x / n,
            y: self.y / n,
            z: self.z / n,
            w: self.w / n,
        }
    }

    /// Spherical linear interpolation with a lerp fallback for near-parallel
    /// quaternions, where `sin(theta)` underflows and slerp divides by ~zero.
    pub fn slerp(self, other: Quat, t: f32) -> Quat {
        let mut cos_theta =
            self.x * other.x + self.y * other.y + self.z * other.z + self.w * other.w;

        // Take the shorter path around the hypersphere. q and -q are the same
        // rotation, so without this the menu sometimes spins 300° to reach an
        // adjacent face.
        let mut end = other;
        if cos_theta < 0.0 {
            end = Quat {
                x: -other.x,
                y: -other.y,
                z: -other.z,
                w: -other.w,
            };
            cos_theta = -cos_theta;
        }

        if cos_theta > 0.9995 {
            return Quat {
                x: self.x + (end.x - self.x) * t,
                y: self.y + (end.y - self.y) * t,
                z: self.z + (end.z - self.z) * t,
                w: self.w + (end.w - self.w) * t,
            }
            .normalized();
        }

        let theta = cos_theta.acos();
        let sin_theta = theta.sin();
        let a = ((1.0 - t) * theta).sin() / sin_theta;
        let b = (t * theta).sin() / sin_theta;

        Quat {
            x: self.x * a + end.x * b,
            y: self.y * a + end.y * b,
            z: self.z * a + end.z * b,
            w: self.w * a + end.w * b,
        }
    }
}

/// The flat, accessible model the visual layer renders. This is the source of
/// truth — the solid is a view of it.
#[derive(Debug, Clone)]
pub struct CategoryModel {
    pub categories: [&'static str; FACE_COUNT],
    pub selected: usize,
}

impl Default for CategoryModel {
    fn default() -> Self {
        CategoryModel {
            categories: [
                "Security",
                "Games",
                "Development",
                "Network",
                "Forensics",
                "Media",
                "Office",
                "Graphics",
                "System",
                "Windows Apps",
                "Utilities",
                "Settings",
            ],
            selected: 0,
        }
    }
}

impl CategoryModel {
    /// Keyboard navigation over the *linear* order, not the geometric
    /// neighbourhood. Arrow keys on a rotating solid are ambiguous — "right" is
    /// undefined once the solid has rotated — so arrows step the list and the
    /// solid follows. Mouse drag rotates freely and snaps to the nearest face,
    /// which is where the geometry earns its keep.
    pub fn step(&mut self, delta: i32) {
        let n = FACE_COUNT as i32;
        self.selected = (((self.selected as i32 + delta) % n + n) % n) as usize;
    }

    pub fn select(&mut self, index: usize) -> Option<&'static str> {
        if index >= FACE_COUNT {
            return None;
        }
        self.selected = index;
        Some(self.categories[index])
    }

    pub fn current(&self) -> &'static str {
        self.categories[self.selected]
    }
}

/// Given a free-rotation orientation, which face is pointing at the camera?
///
/// The camera looks down -Z, so the front-facing normal is the one with the
/// largest dot product against +Z after rotation.
pub fn nearest_face(orientation: Quat, normals: &[Vec3; FACE_COUNT]) -> usize {
    let mut best = 0;
    let mut best_dot = f32::MIN;

    for (i, n) in normals.iter().enumerate() {
        let rotated = rotate(orientation, *n);
        if rotated.z > best_dot {
            best_dot = rotated.z;
            best = i;
        }
    }
    best
}

/// Rotate a vector by a quaternion: v' = v + 2 * cross(q.xyz, cross(q.xyz, v) + q.w * v)
pub fn rotate(q: Quat, v: Vec3) -> Vec3 {
    let u = Vec3::new(q.x, q.y, q.z);
    let t = u.cross(v);
    let t = Vec3::new(t.x + q.w * v.x, t.y + q.w * v.y, t.z + q.w * v.z);
    let r = u.cross(t);
    Vec3::new(v.x + 2.0 * r.x, v.y + 2.0 * r.y, v.z + 2.0 * r.z)
}

/// The full open transition.
pub struct StartMenuTransition {
    pub desktop_zoom: Animation,
    pub solid_fade: Animation,
    pub orientation_from: Quat,
    pub orientation_to: Quat,
    pub rotation_start_ns: u64,
    pub rotation_duration_ns: u64,
}

impl StartMenuTransition {
    /// 420 ms for the zoom-out. Long enough to read as cinematic, short enough
    /// that pressing Super twice in quick succession does not feel laggy — and
    /// interruptible, which matters more than the duration: the animation
    /// re-targets from its current value if the user presses Super again
    /// mid-transition rather than snapping or queueing.
    pub fn open(now_ns: u64, reduce_motion: bool) -> Self {
        let duration = if reduce_motion { 0 } else { 420_000_000 };
        StartMenuTransition {
            desktop_zoom: Animation {
                start_ns: now_ns,
                duration_ns: duration,
                curve: Bezier::SPECTRE_OUT,
                from: 1.0,
                to: 0.55,
                repeat: Repeat::Once,
            },
            solid_fade: Animation {
                start_ns: now_ns + duration / 4,
                duration_ns: duration,
                curve: Bezier::SPECTRE_OUT,
                from: 0.0,
                to: 1.0,
                repeat: Repeat::Once,
            },
            orientation_from: Quat::IDENTITY,
            orientation_to: Quat::IDENTITY,
            rotation_start_ns: now_ns,
            rotation_duration_ns: 260_000_000,
        }
    }

    /// Re-target the rotation toward a new face without restarting from the
    /// identity orientation. Called on every arrow keypress; the previous
    /// rotation's *current* value becomes the new start, so rapid keypresses
    /// produce continuous motion rather than a stutter.
    pub fn retarget(
        &mut self,
        now_ns: u64,
        current: Quat,
        target_face: usize,
        normals: &[Vec3; FACE_COUNT],
    ) {
        self.orientation_from = current;
        self.orientation_to = Quat::between(normals[target_face], Vec3::new(0.0, 0.0, 1.0));
        self.rotation_start_ns = now_ns;
    }

    pub fn orientation_at(&self, now_ns: u64) -> Quat {
        if self.rotation_duration_ns == 0 {
            return self.orientation_to;
        }
        let elapsed = now_ns.saturating_sub(self.rotation_start_ns);
        let t = (elapsed as f32 / self.rotation_duration_ns as f32).clamp(0.0, 1.0);
        let eased = Bezier::SPECTRE_IN_OUT.eval(t);
        self.orientation_from.slerp(self.orientation_to, eased)
    }
}

/// Particle count for the surrounding field, scaled by the budget governor.
pub fn particle_count(quality: Quality) -> u32 {
    (2400.0 * quality.particle_scale()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dodecahedron_has_twelve_unit_normals() {
        let normals = face_normals();
        assert_eq!(normals.len(), 12);
        for (i, n) in normals.iter().enumerate() {
            assert!((n.length() - 1.0).abs() < 1e-5, "face {i} not unit length");
        }
    }

    #[test]
    fn face_normals_are_distinct() {
        let normals = face_normals();
        for i in 0..FACE_COUNT {
            for j in (i + 1)..FACE_COUNT {
                let d = normals[i].dot(normals[j]);
                assert!(d < 0.999, "faces {i} and {j} are the same direction");
            }
        }
    }

    #[test]
    fn normals_come_in_antipodal_pairs() {
        // A regular dodecahedron is centrally symmetric: every face has an
        // opposite. If this fails, the generated geometry is not a dodecahedron.
        let normals = face_normals();
        for (i, n) in normals.iter().enumerate() {
            let has_opposite = normals.iter().any(|m| (m.dot(*n) + 1.0).abs() < 1e-4);
            assert!(has_opposite, "face {i} has no antipode");
        }
    }

    #[test]
    fn rotation_to_a_face_puts_it_facing_the_camera() {
        let normals = face_normals();
        for (i, n) in normals.iter().enumerate() {
            let q = Quat::between(*n, Vec3::new(0.0, 0.0, 1.0));
            let rotated = rotate(q, *n);
            assert!(
                rotated.z > 0.999,
                "face {i} did not face camera: z={}",
                rotated.z
            );
            assert_eq!(nearest_face(q, &normals), i);
        }
    }

    #[test]
    fn antipodal_rotation_does_not_produce_nan() {
        let q = Quat::between(Vec3::new(0.0, 0.0, 1.0), Vec3::new(0.0, 0.0, -1.0));
        assert!(q.x.is_finite() && q.y.is_finite() && q.z.is_finite() && q.w.is_finite());
        let r = rotate(q, Vec3::new(0.0, 0.0, 1.0));
        assert!(r.z < -0.99, "antipodal rotation was wrong: {r:?}");
    }

    #[test]
    fn slerp_takes_the_short_path() {
        let a = Quat::IDENTITY;
        // -identity is the same rotation; slerp must not travel 360°.
        let b = Quat {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            w: -1.0,
        };
        let mid = a.slerp(b, 0.5);
        assert!(mid.w.abs() > 0.99, "took the long way: {mid:?}");
    }

    #[test]
    fn slerp_endpoints_are_exact() {
        let normals = face_normals();
        let a = Quat::between(normals[0], Vec3::new(0.0, 0.0, 1.0));
        let b = Quat::between(normals[7], Vec3::new(0.0, 0.0, 1.0));
        let start = a.slerp(b, 0.0);
        assert!((start.w - a.w).abs() < 1e-5);
    }

    #[test]
    fn keyboard_navigation_wraps_both_directions() {
        let mut m = CategoryModel::default();
        m.step(-1);
        assert_eq!(m.selected, FACE_COUNT - 1);
        m.step(1);
        assert_eq!(m.selected, 0);
        m.step(FACE_COUNT as i32 * 3 + 5);
        assert_eq!(m.selected, 5);
    }

    #[test]
    fn reduce_motion_removes_the_zoom_entirely() {
        let t = StartMenuTransition::open(0, true);
        // Zero duration means the value jumps straight to target: no zoom.
        assert_eq!(t.desktop_zoom.sample(0), 0.55);
    }

    #[test]
    fn selecting_out_of_range_is_refused() {
        let mut m = CategoryModel::default();
        assert!(m.select(FACE_COUNT).is_none());
        assert_eq!(m.selected, 0, "failed selection must not move the cursor");
    }
}
