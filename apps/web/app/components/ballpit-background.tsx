'use client';

import { useRef, useEffect, useMemo } from 'react';
import {
  Clock,
  PerspectiveCamera,
  Scene,
  WebGLRenderer,
  SRGBColorSpace,
  MathUtils,
  Vector2,
  Vector3,
  MeshPhysicalMaterial,
  Color,
  Object3D,
  InstancedMesh,
  PMREMGenerator,
  SphereGeometry,
  AmbientLight,
  PointLight,
  ACESFilmicToneMapping,
  Raycaster,
  Plane,
} from 'three';
import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';

/* ────────────── Three.js Scene Manager ────────────── */

interface SceneConfig {
  canvas: HTMLCanvasElement;
  size: 'parent' | 'window';
}

class ThreeScene {
  #resizeObserver?: ResizeObserver;
  #intersectionObserver?: IntersectionObserver;
  #resizeTimer?: ReturnType<typeof setTimeout>;
  #animationFrameId = 0;
  #clock = new Clock();
  #state = { elapsed: 0, delta: 0 };
  #isAnimating = false;
  #isVisible = false;
  #config: SceneConfig;

  canvas: HTMLCanvasElement;
  camera: PerspectiveCamera;
  scene: Scene;
  renderer: WebGLRenderer;
  size = { width: 0, height: 0, wWidth: 0, wHeight: 0, ratio: 0 };
  onBeforeRender: (state: { elapsed: number; delta: number }) => void = () => {};
  onAfterResize: (size: typeof this.size) => void = () => {};

  constructor(config: SceneConfig) {
    this.#config = config;
    this.canvas = config.canvas;
    this.camera = new PerspectiveCamera(50, 1, 0.1, 100);
    this.scene = new Scene();
    this.renderer = new WebGLRenderer({
      canvas: this.canvas,
      powerPreference: 'high-performance',
      alpha: true,
      antialias: true,
    });
    this.renderer.outputColorSpace = SRGBColorSpace;
    this.canvas.style.display = 'block';
    this.#initObservers();
    this.resize();
  }

  #initObservers() {
    const parent = this.#config.size === 'parent' ? (this.canvas.parentNode as Element) : null;
    if (parent) {
      this.#resizeObserver = new ResizeObserver(() => this.#onResize());
      this.#resizeObserver.observe(parent);
    } else {
      window.addEventListener('resize', this.#onResizeBound);
    }
    this.#intersectionObserver = new IntersectionObserver(
      (entries) => {
        const visible = entries[0]?.isIntersecting ?? false;
        this.#isAnimating = visible;
        if (visible) {
          this.#start();
        } else {
          this.#stop();
        }
      },
      { threshold: 0 },
    );
    this.#intersectionObserver.observe(this.canvas);
    document.addEventListener('visibilitychange', this.#onVisibilityBound);
  }

  #onResizeBound = () => this.#onResize();
  #onVisibilityBound = () => {
    if (this.#isAnimating) {
      if (document.hidden) {
        this.#stop();
      } else {
        this.#start();
      }
    }
  };

  #onResize() {
    if (this.#resizeTimer) clearTimeout(this.#resizeTimer);
    this.#resizeTimer = setTimeout(() => this.resize(), 100);
  }

  resize() {
    const parent = this.#config.size === 'parent' ? (this.canvas.parentNode as HTMLElement) : null;
    const w = parent ? parent.offsetWidth : window.innerWidth;
    const h = parent ? parent.offsetHeight : window.innerHeight;
    this.size.width = w;
    this.size.height = h;
    this.size.ratio = w / h;
    this.camera.aspect = this.size.ratio;
    this.camera.updateProjectionMatrix();
    const fovRad = (this.camera.fov * Math.PI) / 180;
    this.size.wHeight = 2 * Math.tan(fovRad / 2) * this.camera.position.z;
    this.size.wWidth = this.size.wHeight * this.camera.aspect;
    this.renderer.setSize(w, h);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.onAfterResize(this.size);
  }

  #start() {
    if (this.#isVisible) return;
    this.#isVisible = true;
    this.#clock.start();
    const frame = () => {
      this.#animationFrameId = requestAnimationFrame(frame);
      this.#state.delta = this.#clock.getDelta();
      this.#state.elapsed += this.#state.delta;
      this.onBeforeRender(this.#state);
      this.renderer.render(this.scene, this.camera);
    };
    frame();
  }

  #stop() {
    if (!this.#isVisible) return;
    cancelAnimationFrame(this.#animationFrameId);
    this.#isVisible = false;
    this.#clock.stop();
  }

  dispose() {
    this.#stop();
    this.#resizeObserver?.disconnect();
    this.#intersectionObserver?.disconnect();
    window.removeEventListener('resize', this.#onResizeBound);
    document.removeEventListener('visibilitychange', this.#onVisibilityBound);
    this.scene.clear();
    this.renderer.dispose();
  }
}

/* ────────────── Physics Engine ────────────── */

interface PhysicsConfig {
  count: number;
  size0: number;
  minSize: number;
  maxSize: number;
  maxX: number;
  maxY: number;
  maxZ: number;
  gravity: number;
  friction: number;
  wallBounce: number;
  maxVelocity: number;
  controlSphere0: boolean;
}

class SpherePhysics {
  config: PhysicsConfig;
  positions: Float32Array;
  velocities: Float32Array;
  sizes: Float32Array;
  center = new Vector3();

  constructor(config: PhysicsConfig) {
    this.config = config;
    this.positions = new Float32Array(3 * config.count);
    this.velocities = new Float32Array(3 * config.count);
    this.sizes = new Float32Array(config.count);
    this.#scatter();
    this.#assignSizes();
  }

  #scatter() {
    const { count, maxX, maxY, maxZ } = this.config;
    this.center.toArray(this.positions, 0);
    for (let i = 1; i < count; i++) {
      const b = 3 * i;
      this.positions[b] = MathUtils.randFloatSpread(2 * maxX);
      this.positions[b + 1] = MathUtils.randFloatSpread(2 * maxY);
      this.positions[b + 2] = MathUtils.randFloatSpread(2 * maxZ);
    }
  }

  #assignSizes() {
    const { count, size0, minSize, maxSize } = this.config;
    this.sizes[0] = size0;
    for (let i = 1; i < count; i++) this.sizes[i] = MathUtils.randFloat(minSize, maxSize);
  }

  update(dt: number) {
    const { config, center, positions: pos, sizes, velocities: vel } = this;
    const start = config.controlSphere0 ? 1 : 0;

    if (config.controlSphere0) {
      new Vector3().fromArray(pos, 0).lerp(center, 0.1).toArray(pos, 0);
      vel[0] = vel[1] = vel[2] = 0;
    }

    for (let i = start; i < config.count; i++) {
      const b = 3 * i;
      const si = sizes[i]!;
      const p = new Vector3().fromArray(pos, b);
      const v = new Vector3().fromArray(vel, b);
      v.y -= dt * config.gravity * si;
      v.multiplyScalar(config.friction);
      v.clampLength(0, config.maxVelocity);
      p.add(v);

      for (let j = i + 1; j < config.count; j++) {
        const ob = 3 * j;
        const sj = sizes[j]!;
        const op = new Vector3().fromArray(pos, ob);
        const d = new Vector3().subVectors(op, p);
        const dist = d.length();
        const sum = si + sj;
        if (dist < sum) {
          const half = (sum - dist) * 0.5;
          d.normalize();
          p.addScaledVector(d, -half);
          op.addScaledVector(d, half);
          p.toArray(pos, b);
          op.toArray(pos, ob);
        }
      }

      if (Math.abs(p.x) + si > config.maxX) {
        p.x = Math.sign(p.x) * (config.maxX - si);
        v.x *= -config.wallBounce;
      }
      if (p.y - si < -config.maxY) {
        p.y = -config.maxY + si;
        v.y *= -config.wallBounce;
      }
      if (Math.abs(p.z) + si > config.maxZ) {
        p.z = Math.sign(p.z) * (config.maxZ - si);
        v.z *= -config.wallBounce;
      }
      p.toArray(pos, b);
      v.toArray(vel, b);
    }
  }
}

/* ────────────── Instanced Sphere Mesh ────────────── */

const _obj = new Object3D();

interface SphereCloudConfig extends PhysicsConfig {
  colors: (string | Color)[];
  materialParams: Record<string, number>;
  lightIntensity: number;
  ambientIntensity: number;
}

class SphereCloud extends InstancedMesh {
  physics: SpherePhysics;
  ambient: AmbientLight;
  point: PointLight;

  constructor(renderer: WebGLRenderer, cfg: SphereCloudConfig) {
    const pmrem = new PMREMGenerator(renderer);
    // RoomEnvironment may accept renderer as optional argument depending on version
    const envTex = pmrem.fromScene(new RoomEnvironment() as Scene).texture;
    pmrem.dispose();

    const geo = new SphereGeometry(1, 24, 24);
    const mat = new MeshPhysicalMaterial({ envMap: envTex, ...cfg.materialParams });
    super(geo, mat, cfg.count);

    this.physics = new SpherePhysics(cfg);
    this.ambient = new AmbientLight(0xffffff, cfg.ambientIntensity);
    this.add(this.ambient);
    this.point = new PointLight(0xffffff, cfg.lightIntensity, 100, 1);
    this.add(this.point);
    this.applyColors(cfg.colors);
  }

  applyColors(colors: (string | Color)[]) {
    if (!colors?.length) return;
    const objs = colors.map((c) => (c instanceof Color ? c : new Color(c)));
    for (let i = 0; i < this.count; i++) this.setColorAt(i, objs[i % objs.length]!);
    if (this.instanceColor) this.instanceColor.needsUpdate = true;
  }

  tick(dt: number, controlSphere0: boolean) {
    this.physics.update(dt);
    for (let i = 0; i < this.count; i++) {
      _obj.position.fromArray(this.physics.positions, 3 * i);
      _obj.scale.setScalar(this.physics.sizes[i]!);
      _obj.updateMatrix();
      this.setMatrixAt(i, _obj.matrix);
    }
    this.instanceMatrix.needsUpdate = true;
    if (controlSphere0) this.point.position.fromArray(this.physics.positions, 0);
  }
}

/* ────────────── Pointer tracking ────────────── */

const pointer = new Vector2();
function onPointerMove(e: PointerEvent) {
  pointer.set((e.clientX / window.innerWidth) * 2 - 1, -(e.clientY / window.innerHeight) * 2 + 1);
}

/* ────────────── Config defaults ────────────── */

const DEFAULTS: SphereCloudConfig = {
  count: 150,
  materialParams: { metalness: 0.6, roughness: 0.35, clearcoat: 1, clearcoatRoughness: 0.15 },
  minSize: 0.3,
  maxSize: 0.75,
  size0: 1.0,
  gravity: 0.4,
  friction: 0.995,
  wallBounce: 0.2,
  maxVelocity: 0.1,
  maxX: 10,
  maxY: 10,
  maxZ: 10,
  controlSphere0: true,
  lightIntensity: 3,
  ambientIntensity: 1.5,
  colors: ['#3a7a5c', '#286f58', '#4a9a72', '#1d5a44', '#5eb88a'],
};

/* ────────────── React Component ────────────── */

export interface BallpitBackgroundProps {
  /** Partial overrides for sphere configuration */
  config?: Partial<SphereCloudConfig>;
  /** Whether the main sphere follows the cursor */
  followCursor?: boolean;
  /** Extra class name on the canvas wrapper */
  className?: string;
}

export function BallpitBackground({
  config: overrides = {},
  followCursor = true,
  className = '',
}: BallpitBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const cfg = useMemo<SphereCloudConfig>(
    () => ({ ...DEFAULTS, ...overrides }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [JSON.stringify(overrides)],
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const three = new ThreeScene({ canvas, size: 'parent' });
    three.renderer.toneMapping = ACESFilmicToneMapping;
    three.camera.position.set(0, 0, 20);

    const cloud = new SphereCloud(three.renderer, cfg);
    three.scene.add(cloud);

    const raycaster = new Raycaster();
    const plane = new Plane(new Vector3(0, 0, 1), 0);
    const hit = new Vector3();

    if (followCursor) window.addEventListener('pointermove', onPointerMove);

    three.onBeforeRender = ({ delta }) => {
      if (followCursor) {
        raycaster.setFromCamera(pointer, three.camera);
        if (raycaster.ray.intersectPlane(plane, hit)) {
          cloud.physics.center.copy(hit);
        }
      }
      cloud.tick(delta, cfg.controlSphere0);
    };

    three.onAfterResize = (size) => {
      cloud.physics.config.maxX = size.wWidth / 2;
      cloud.physics.config.maxY = size.wHeight / 2;
      cloud.physics.config.maxZ = size.wWidth / 4;
    };

    return () => {
      if (followCursor) window.removeEventListener('pointermove', onPointerMove);
      three.dispose();
    };
  }, [cfg, followCursor]);

  return (
    <div className={`ballpit-container ${className}`.trim()}>
      <canvas ref={canvasRef} />
    </div>
  );
}
