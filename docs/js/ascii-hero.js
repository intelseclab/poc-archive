// Hero 3D model asset: "Bomb" by giga (https://sketchfab.com/gits3d) licensed under CC BY 4.0
import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';

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
    holder.position.y = -0.25;
    return holder;
  };

  const fallbackMesh = () => fit(new THREE.Mesh(
    new THREE.TorusKnotGeometry(1, 0.34, 220, 32),
    new THREE.MeshStandardMaterial({ color: 0x10b981, roughness: 0.35, metalness: 0.15 })
  ));

  const renderer = new THREE.WebGLRenderer({ antialias: !raw });
  renderer.setPixelRatio(1);

  // Recolor model texture: keep fire sparks (orange/red), map bomb body and collar to emerald green
  const recolorTexture = (texture) => {
    const img = texture.image;
    if (!img) return texture;
    const canvas = document.createElement('canvas');
    canvas.width = img.width || 512;
    canvas.height = img.height || 512;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    const idata = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const d = idata.data;
    for (let i = 0; i < d.length; i += 4) {
      const r = d[i], g = d[i + 1], b = d[i + 2];
      // Keep fire colors (high red, low blue: orange & red sparks)
      const isFire = (r > 180 && b < 60);
      if (!isFire) {
        if (r > 70) {
          // Fuse/collar: light mint (#a7f3d0)
          d[i] = 167;
          d[i + 1] = 243;
          d[i + 2] = 208;
        } else {
          // Bomb body: emerald green (#10b981)
          d[i] = 16;
          d[i + 1] = 185;
          d[i + 2] = 129;
        }
      }
    }
    ctx.putImageData(idata, 0, 0);
    const newTex = new THREE.CanvasTexture(canvas);
    newTex.flipY = texture.flipY;
    if (texture.colorSpace) newTex.colorSpace = texture.colorSpace;
    newTex.needsUpdate = true;
    return newTex;
  };

  const normalizeMaterials = (root) => {
    root.traverse((o) => {
      if (o.isMesh && o.material) {
        if (o.material.map && o.material.map.image) {
          o.material.map = recolorTexture(o.material.map);
        }
        o.material.emissive = new THREE.Color(0x064e3b);
        o.material.roughness = 0.45;
        o.material.metalness = 0;
      }
    });
  };

  // High-performance DOM AsciiEffect:
  // - Zero-span background: empty/black spaces are emitted as plain text, eliminating ~6,000 DOM nodes/frame
  // - Run-length color grouping: merges consecutive characters with identical RGB into a single span
  // - willReadFrequently: true: eliminates GPU stalls and synchronous readback warnings
  class FastAsciiEffect {
    constructor(rend, charSet = ' .:-=+*#%@', options = {}) {
      const fResolution = options.resolution || 0.15;
      const iScale = options.scale || 1;
      const bColor = options.color || false;
      const bInvert = options.invert || false;

      let width = 0, height = 0;
      let iWidth = 0, iHeight = 0;

      const domElement = document.createElement('div');
      domElement.style.cursor = 'default';

      const oAscii = document.createElement('table');
      oAscii.cellSpacing = '0';
      oAscii.cellPadding = '0';
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      tr.appendChild(td);
      oAscii.appendChild(tr);
      domElement.appendChild(oAscii);

      const oCanvasImg = rend.domElement;
      const oCanvas = document.createElement('canvas');
      const oCtx = oCanvas.getContext('2d', { willReadFrequently: true });

      const aCharList = charSet || ' .:-=+*#%@';
      const fFontSize = (2 / fResolution) * iScale;
      const fLineHeight = (2 / fResolution) * iScale;

      const oStyle = oAscii.style;
      oStyle.whiteSpace = 'pre';
      oStyle.margin = '0px';
      oStyle.padding = '0px';
      oStyle.letterSpacing = '-1px';
      oStyle.fontFamily = '"JetBrains Mono", ui-monospace, monospace';
      oStyle.fontSize = `${fFontSize}px`;
      oStyle.lineHeight = `${fLineHeight}px`;
      oStyle.textAlign = 'left';

      this.domElement = domElement;

      this.setSize = function (w, h) {
        width = w;
        height = h;
        rend.setSize(w, h);
        iWidth = Math.floor(width * fResolution);
        iHeight = Math.floor(height * fResolution);
        oCanvas.width = iWidth;
        oCanvas.height = iHeight;
        td.style.display = 'block';
        td.style.width = `${width}px`;
        td.style.height = `${height}px`;
        td.style.overflow = 'hidden';
      };

      const asciifyImage = () => {
        oCtx.clearRect(0, 0, iWidth, iHeight);
        oCtx.drawImage(oCanvasImg, 0, 0, iWidth, iHeight);
        const d = oCtx.getImageData(0, 0, iWidth, iHeight).data;

        let strChars = '';
        const charLen = aCharList.length - 1;

        for (let y = 0; y < iHeight; y += 2) {
          let curColor = null;
          let curText = '';

          for (let x = 0; x < iWidth; x++) {
            const iOffset = (y * iWidth + x) * 4;
            const r = d[iOffset];
            const g = d[iOffset + 1];
            const b = d[iOffset + 2];
            const a = d[iOffset + 3];

            let fBrightness = (0.3 * r + 0.59 * g + 0.11 * b) / 255;
            if (a === 0) fBrightness = 1;

            let iCharIdx = Math.floor((1 - fBrightness) * charLen);
            if (bInvert) iCharIdx = charLen - iCharIdx;

            const strThisChar = aCharList[iCharIdx];
            const isSpace = (!strThisChar || strThisChar === ' ' || (r === 0 && g === 0 && b === 0));

            if (!bColor || isSpace) {
              if (curColor !== null) {
                strChars += `<span style="color:${curColor}">${curText}</span>`;
                curColor = null;
                curText = '';
              }
              curText += (strThisChar === ' ' || !strThisChar) ? '&nbsp;' : strThisChar;
            } else {
              const colorStr = `rgb(${r},${g},${b})`;
              if (colorStr === curColor) {
                curText += strThisChar;
              } else {
                if (curText) {
                  strChars += curColor ? `<span style="color:${curColor}">${curText}</span>` : curText;
                }
                curColor = colorStr;
                curText = strThisChar;
              }
            }
          }

          if (curText) {
            strChars += curColor ? `<span style="color:${curColor}">${curText}</span>` : curText;
          }
          strChars += '<br/>';
        }

        td.innerHTML = strChars;
      };

      this.render = function (sc, cam) {
        rend.render(sc, cam);
        asciifyImage();
      };
    }
  }

  let effect = null;
  if (raw) {
    renderer.setSize(SIZE, SIZE);
    mount.appendChild(renderer.domElement);
  } else {
    effect = new FastAsciiEffect(renderer, ' .:-=+*#%@', { invert: true, resolution: RESOLUTION, color: true });
    effect.setSize(SIZE, SIZE);
    const table = effect.domElement.firstElementChild;
    table.style.fontFamily = '"JetBrains Mono", ui-monospace, monospace';
    // Compensate so each char advance = 1/resolution:
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

  let dragging = false;
  let lastX = 0;
  let velY = 0;
  let dirty = true;

  mount.addEventListener('pointerdown', (e) => {
    dragging = true;
    lastX = e.clientX;
    velY = 0;
    mount.style.cursor = 'grabbing';
    mount.setPointerCapture(e.pointerId);
  });

  mount.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const dx = e.clientX - lastX;
    lastX = e.clientX;
    pivot.rotation.y += dx * 0.005;
    velY = dx * 0.005;
    dirty = true;
  });

  const endDrag = () => {
    dragging = false;
    mount.style.cursor = 'grab';
  };
  mount.addEventListener('pointerup', endDrag);
  mount.addEventListener('pointercancel', endDrag);

  // Lifecycle optimizations: pause when scrolled off-screen or tab is hidden
  let isVisible = true;
  let running = false;

  const TARGET_FPS = 60; // Silky smooth 60 FPS enabled by FastAsciiEffect (<2ms per frame)
  const FRAME_INTERVAL = 1000 / TARGET_FPS;
  let lastFrameTime = 0;

  const startLoop = () => {
    if (!running && isVisible && !document.hidden) {
      running = true;
      requestAnimationFrame(tick);
    }
  };

  const stopLoop = () => {
    running = false;
  };

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(
      ([entry]) => {
        isVisible = entry.isIntersecting;
        if (isVisible) startLoop();
        else stopLoop();
      },
      { threshold: 0.05 }
    );
    observer.observe(mount);
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stopLoop();
    else if (isVisible) startLoop();
  });

  const tick = (now = performance.now()) => {
    if (!running) return;

    requestAnimationFrame(tick);

    const elapsed = now - lastFrameTime;
    if (elapsed < FRAME_INTERVAL && !dragging) return;
    lastFrameTime = now - (elapsed % FRAME_INTERVAL);

    if (!dragging && Math.abs(velY) > 0.0001) {
      pivot.rotation.y += velY;
      velY *= 0.92;
      dirty = true;
    }
    if (dirty) {
      if (effect) effect.render(scene, camera);
      else renderer.render(scene, camera);
      dirty = false;
    }
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

  startLoop();
}
