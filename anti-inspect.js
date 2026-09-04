/**
 * PILAR 5: Anti-Inspect Protection Module (Stand-alone for tests and browser)
 * File: anti-inspect.js
 */

function initAntiInspect(doc = typeof document !== "undefined" ? document : null) {
  if (!doc) return () => {};

  const handleContextMenu = (e) => {
    const target = e.target;
    if (
      target &&
      (target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable)
    ) {
      return;
    }
    e.preventDefault();
  };

  const handleKeyDown = (e) => {
    const isCtrlOrCmd = e.ctrlKey || e.metaKey;
    const isShift = e.shiftKey;
    const isAltOrOption = e.altKey;
    const key = (e.key || "").toUpperCase();
    const keyCode = e.keyCode || e.which;

    // F12
    if (key === "F12" || keyCode === 123) {
      e.preventDefault();
      if (e.stopPropagation) e.stopPropagation();
      return;
    }

    // Ctrl+Shift+I / Cmd+Option+I
    if (isCtrlOrCmd && (isShift || isAltOrOption) && (key === "I" || keyCode === 73)) {
      e.preventDefault();
      if (e.stopPropagation) e.stopPropagation();
      return;
    }

    // Ctrl+Shift+J / Cmd+Option+J
    if (isCtrlOrCmd && (isShift || isAltOrOption) && (key === "J" || keyCode === 74)) {
      e.preventDefault();
      if (e.stopPropagation) e.stopPropagation();
      return;
    }

    // Ctrl+Shift+C / Cmd+Option+C
    if (isCtrlOrCmd && (isShift || isAltOrOption) && (key === "C" || keyCode === 67)) {
      e.preventDefault();
      if (e.stopPropagation) e.stopPropagation();
      return;
    }

    // Ctrl+U / Cmd+Option+U
    if (isCtrlOrCmd && (key === "U" || keyCode === 85)) {
      e.preventDefault();
      if (e.stopPropagation) e.stopPropagation();
      return;
    }

    // Ctrl+S / Cmd+S
    if (isCtrlOrCmd && (key === "S" || keyCode === 83)) {
      e.preventDefault();
      if (e.stopPropagation) e.stopPropagation();
      return;
    }
  };

  const handleDragStart = (e) => {
    const target = e.target;
    if (target && target.tagName === "IMG") {
      e.preventDefault();
    }
  };

  doc.addEventListener("contextmenu", handleContextMenu, { capture: true });
  doc.addEventListener("keydown", handleKeyDown, { capture: true });
  doc.addEventListener("dragstart", handleDragStart, { capture: true });

  return () => {
    doc.removeEventListener("contextmenu", handleContextMenu, { capture: true });
    doc.removeEventListener("keydown", handleKeyDown, { capture: true });
    doc.removeEventListener("dragstart", handleDragStart, { capture: true });
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { initAntiInspect };
}
