/* ==========================================================
   CyberWEB Radar Loader
   Part 1
   ========================================================== */

function initRadar(canvas) {

  const ctx = canvas.getContext("2d");
  const DPR = window.devicePixelRatio || 1;

  let width;
  let height;

  let centerX;
  let centerY;

  let radius;
  let sweepAngle = 0;

  const blips = [];

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * DPR;
    canvas.height = height * DPR;
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

    centerX = width / 2;
    centerY = height / 2;
    radius = Math.min(width, height) * 1;
  }

  resize();

  window.addEventListener("resize", resize);

  function createBlip() {

    if (blips.length > 10)
      return;

    blips.push({
      angle: Math.random() * Math.PI * 2,
      distance: Math.random() * 0.9 + 0.05,
      alpha: 1
    });

  }

  setInterval(createBlip, 700);

  function drawBackground() {

    const bg = ctx.createRadialGradient(
      centerX,
      centerY,
      0,
      centerX,
      centerY,
      radius
    );

    bg.addColorStop(0, "rgba(62, 53, 142, 0.51)");   // Center — violet glow
    bg.addColorStop(0.45, "#070a14");
    bg.addColorStop(1, "#030508");   // Edges

    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, width, height);

  }

  function drawGrid() {
    ctx.strokeStyle = "rgba(80, 70, 170, 0.4)";
    ctx.lineWidth = 0.8;
    for (let i = 1; i <= 8; i++) {
      ctx.beginPath();
      ctx.arc(
        centerX,
        centerY,
        radius * i / 6,
        0,
        Math.PI * 2
      );

      ctx.stroke();
    }

    const spokes = 8; // 8 = every 45°, 16 = every 22.5°

    ctx.beginPath();

    for (let i = 0; i < spokes; i++) {
      const angle = (Math.PI * 2 * i) / spokes;

      ctx.moveTo(centerX, centerY);

      ctx.lineTo(
        centerX + Math.cos(angle) * radius,
        centerY + Math.sin(angle) * radius
      );
    }

    ctx.stroke();
  }

  function drawSweep() {
    ctx.save();
    ctx.translate(centerX, centerY);
    ctx.rotate(sweepAngle);
    const gradient = ctx.createRadialGradient(0, 0, 0, 0, 0, radius);

    gradient.addColorStop(0.0, "rgba(114,99,255,0.55)");
    gradient.addColorStop(0.4, "rgba(114,99,255,0.25)");
    gradient.addColorStop(1.0, "rgba(114,99,255,0)");

    ctx.fillStyle = gradient;

    ctx.beginPath();

    ctx.moveTo(0, 0);

    ctx.arc(

      0,

      0,

      radius,

      -0.50,

      0.50

    );

    ctx.closePath();

    ctx.fill();

    ctx.restore();

  }

  function drawBlips() {

    for (let i = blips.length - 1; i >= 0; i--) {

      const blip = blips[i];

      blip.alpha -= 0.003;

      if (blip.alpha <= 0) {
        blips.splice(i, 1);
        continue;
      }

      const x =
        centerX +
        Math.cos(blip.angle) *
        radius *
        blip.distance;

      const y =
        centerY +
        Math.sin(blip.angle) *
        radius *
        blip.distance;

      const diff = Math.abs(
        Math.atan2(
          Math.sin(sweepAngle - blip.angle),
          Math.cos(sweepAngle - blip.angle)
        )
      );

      const intensity = diff < 0.18 ? 1 : 0.35;

      ctx.beginPath();

      ctx.fillStyle =
        `rgba(53,229,224,${blip.alpha * intensity})`;

      ctx.arc(
        x,
        y,
        3,
        0,
        Math.PI * 2
      );

      ctx.fill();
    }

  }

  function drawCenter() {

    ctx.beginPath();

    ctx.fillStyle = "#7263ff";

    ctx.arc(
      centerX,
      centerY,
      24, // Same radius as the old glow
      0,
      Math.PI * 2
    );

    ctx.fill();

  }

  function animate() {

    drawBackground();

    drawGrid();

    drawSweep();

    drawBlips();

    drawCenter();

    sweepAngle += 0.012;

    if (sweepAngle > Math.PI * 2)
      sweepAngle = 0;

    requestAnimationFrame(animate);

  }

  animate();

  return function () {

    window.removeEventListener(
      "resize",
      resize
    );

  };

}