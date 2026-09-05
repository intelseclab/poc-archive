import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { AsciiEffect } from 'three/addons/effects/AsciiEffect.js';

const mount = document.getElementById('ascii-hero');

if (mount) {
  const SIZE = 360;
  const RESOLUTION = 0.35;
  // ?raw — render the plain WebGL canvas instead of the ASCII effect (debug view)
  const raw = new URLSearchParams(location.search).has('raw');

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 50);
  camera.position.set(0, 0.4, 4.6);
  camera.lookAt(0, 0, 0);

  scene.add(new THREE.AmbientLight(0xffffff, 0.5));
  const key = new THREE.DirectionalLight(0xffffff, 3.2);
  key.position.set(2.5, 3, 3.5);
  scene.add(key);
  const fill = new THREE.DirectionalLight(0xffffff, 1.0);
  fill.position.set(-3, -1.5, -2);
  scene.add(fill);

  const pivot = new THREE.Group();
  scene.add(pivot);

  const fit = (obj) => {
    const box = new THREE.Box3().setFromObject(obj);
    const size = box.getSize(new THREE.Vector3());
    const center = box.getCenter(new THREE.Vector3());
    const holder = new THREE.Group();
    obj.position.set(-center.x, -center.y, -center.z);
    holder.add(obj);
    holder.scale.setScalar(2.8 / (Math.max(size.x, size.y, size.z) || 1));
    return holder;
  };

  const fallbackMesh = () => fit(new THREE.Mesh(
    new THREE.TorusKnotGeometry(1, 0.34, 220, 32),
    new THREE.MeshStandardMaterial({ roughness: 0.35, metalness: 0.15 })
  ));

  const renderer = new THREE.WebGLRenderer({ antialias: !raw });
  renderer.setPixelRatio(1);

  // ASCII readability comes from silhouette + shading, not texture detail:
  // swap any textured materials for a matte mid-gray with a wide ramp.
  const normalizeMaterials = (root) => {
    root.traverse((o) => {
      if (o.isMesh) {
        o.material = new THREE.MeshStandardMaterial({ color: 0xd9d9d9, roughness: 0.45, metalness: 0 });
      }
    });
  };

  let effect = null;
  if (raw) {
    renderer.setSize(SIZE, SIZE);
    mount.appendChild(renderer.domElement);
  } else {
    effect = new AsciiEffect(renderer, ' .:-=+*#%@', { invert: true, resolution: RESOLUTION });
    effect.setSize(SIZE, SIZE);
    const table = effect.domElement.firstElementChild;
    table.style.fontFamily = '"JetBrains Mono", ui-monospace, monospace';
    // AsciiEffect's letter-spacing presets assume resolution 0.2; at other
    // resolutions the char grid is narrower than the canvas and the image
    // squashes horizontally. Compensate so each char advance = 1/resolution:
    // advance = 0.6em (mono) × fontSize(2/res) + spacing = 1/res → spacing = -0.2/res.
    table.style.letterSpacing = `${-0.2 / RESOLUTION}px`;
    effect.domElement.style.backgroundColor = 'transparent';
    mount.appendChild(effect.domElement);
    const paint = () => {
      const dark = document.documentElement.classList.contains('dark');
      effect.domElement.style.color = dark ? '#10b981' : '#059669';
    };
    paint();
    new MutationObserver(paint).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
  }

  // Drag-to-rotate with inertia
  mount.style.touchAction = 'none';
  mount.style.cursor = 'grab';

  const clampPitch = (v) => Math.max(-Math.PI / 2, Math.min(Math.PI / 2, v));

  let dragging = false;
  let lastX = 0;
  let lastY = 0;
  let velX = 0;
  let velY = 0;
  let dirty = true;

  mount.addEventListener('pointerdown', (e) => {
    dragging = true;
    lastX = e.clientX;
    lastY = e.clientY;
    velX = velY = 0;
    mount.style.cursor = 'grabbing';
    mount.setPointerCapture(e.pointerId);
  });

  mount.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const dx = e.clientX - lastX;
    const dy = e.clientY - lastY;
    lastX = e.clientX;
    lastY = e.clientY;
    pivot.rotation.y += dx * 0.01;
    pivot.rotation.x = clampPitch(pivot.rotation.x + dy * 0.01);
    velY = dx * 0.01;
    velX = dy * 0.01;
    dirty = true;
  });

  const endDrag = () => {
    dragging = false;
    mount.style.cursor = 'grab';
  };
  mount.addEventListener('pointerup', endDrag);
  mount.addEventListener('pointercancel', endDrag);

  const tick = () => {
    if (!dragging && (Math.abs(velX) > 0.0001 || Math.abs(velY) > 0.0001)) {
      pivot.rotation.y += velY;
      pivot.rotation.x = clampPitch(pivot.rotation.x + velX);
      velX *= 0.95;
      velY *= 0.95;
      dirty = true;
    }
    if (dirty) {
      if (effect) effect.render(scene, camera);
      else renderer.render(scene, camera);
      dirty = false;
    }
    requestAnimationFrame(tick);
  };

  new GLTFLoader().load(
    mount.dataset.model,
    (gltf) => {
      normalizeMaterials(gltf.scene);
      pivot.add(fit(gltf.scene));
      dirty = true;
    },
    undefined,
    () => {
      pivot.add(fallbackMesh());
      dirty = true;
    }
  );

  requestAnimationFrame(tick);
}
