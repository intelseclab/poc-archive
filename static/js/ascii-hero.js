import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { AsciiEffect } from 'three/addons/effects/AsciiEffect.js';

const mount = document.getElementById('ascii-hero');

if (mount) {
  const SIZE = 280;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 50);
  camera.position.set(0, 0.4, 4.6);
  camera.lookAt(0, 0, 0);

  scene.add(new THREE.AmbientLight(0xffffff, 1.1));
  const key = new THREE.DirectionalLight(0xffffff, 2.4);
  key.position.set(2.5, 3, 3.5);
  scene.add(key);
  const fill = new THREE.DirectionalLight(0xffffff, 0.9);
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

  const renderer = new THREE.WebGLRenderer({ antialias: false });
  renderer.setPixelRatio(1);

  const effect = new AsciiEffect(renderer, ' .:-=+*#%@', { invert: true, resolution: 0.2 });
  effect.setSize(SIZE, SIZE);
  effect.domElement.firstElementChild.style.fontFamily = '"JetBrains Mono", ui-monospace, monospace';
  effect.domElement.style.backgroundColor = 'transparent';
  mount.appendChild(effect.domElement);

  const paint = () => {
    const dark = document.documentElement.classList.contains('dark');
    effect.domElement.style.color = dark ? '#10b981' : '#059669';
  };
  paint();
  new MutationObserver(paint).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

  new GLTFLoader().load(
    mount.dataset.model,
    (gltf) => {
      pivot.add(fit(gltf.scene));
      effect.render(scene, camera);
    },
    undefined,
    () => {
      pivot.add(fallbackMesh());
      effect.render(scene, camera);
    }
  );
}
