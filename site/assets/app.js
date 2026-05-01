const canvas = document.getElementById("network-canvas");
const ctx = canvas.getContext("2d", { alpha: true });

const palette = ["#f2b84b", "#61d394", "#74d7ec", "#ff6b5f", "#f7f3e8"];
let width = 0;
let height = 0;
let nodes = [];
let packets = [];
let last = 0;

function resize() {
  const scale = Math.min(window.devicePixelRatio || 1, 2);
  width = window.innerWidth;
  height = window.innerHeight;
  canvas.width = Math.floor(width * scale);
  canvas.height = Math.floor(height * scale);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx.setTransform(scale, 0, 0, scale, 0, 0);
  buildNetwork();
}

function buildNetwork() {
  const count = width < 700 ? 22 : 38;
  nodes = Array.from({ length: count }, (_, index) => {
    const ring = index % 7;
    return {
      x: 40 + Math.random() * Math.max(width - 80, 1),
      y: 70 + Math.random() * Math.max(height - 140, 1),
      vx: (Math.random() - 0.5) * 0.22,
      vy: (Math.random() - 0.5) * 0.22,
      r: 2.2 + (ring % 3),
      color: palette[ring % palette.length],
    };
  });
  packets = Array.from({ length: Math.max(10, Math.floor(count / 2)) }, () => spawnPacket());
}

function nearestPair() {
  const a = nodes[Math.floor(Math.random() * nodes.length)];
  let b = nodes[Math.floor(Math.random() * nodes.length)];
  let best = Infinity;
  for (const candidate of nodes) {
    if (candidate === a) continue;
    const dist = Math.hypot(candidate.x - a.x, candidate.y - a.y);
    if (dist < best && dist > 80) {
      best = dist;
      b = candidate;
    }
  }
  return { a, b };
}

function spawnPacket() {
  const { a, b } = nearestPair();
  return {
    a,
    b,
    t: Math.random(),
    speed: 0.12 + Math.random() * 0.2,
    color: palette[Math.floor(Math.random() * palette.length)],
  };
}

function step(time) {
  const elapsed = Math.min((time - last) / 1000 || 0.016, 0.04);
  last = time;
  ctx.clearRect(0, 0, width, height);

  for (const node of nodes) {
    node.x += node.vx * elapsed * 60;
    node.y += node.vy * elapsed * 60;
    if (node.x < 24 || node.x > width - 24) node.vx *= -1;
    if (node.y < 24 || node.y > height - 24) node.vy *= -1;
  }

  ctx.lineWidth = 1;
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      const a = nodes[i];
      const b = nodes[j];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      if (dist > 170) continue;
      const alpha = Math.max(0, 1 - dist / 170) * 0.18;
      ctx.strokeStyle = `rgba(247, 243, 232, ${alpha})`;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }
  }

  for (const packet of packets) {
    packet.t += packet.speed * elapsed;
    if (packet.t >= 1) Object.assign(packet, spawnPacket());
    const x = packet.a.x + (packet.b.x - packet.a.x) * packet.t;
    const y = packet.a.y + (packet.b.y - packet.a.y) * packet.t;
    ctx.fillStyle = packet.color;
    ctx.beginPath();
    ctx.arc(x, y, 3.2, 0, Math.PI * 2);
    ctx.fill();
  }

  for (const node of nodes) {
    ctx.fillStyle = node.color;
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = "rgba(247, 243, 232, 0.18)";
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.r + 7, 0, Math.PI * 2);
    ctx.stroke();
  }

  requestAnimationFrame(step);
}

window.addEventListener("resize", resize, { passive: true });
resize();
requestAnimationFrame(step);
