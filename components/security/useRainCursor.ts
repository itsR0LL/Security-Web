"use client";

import { useCallback, useEffect, useRef } from "react";

export function useRainCursor() {
  const cursorRef = useRef<HTMLDivElement | null>(null);
  const xLineRef = useRef<HTMLElement | null>(null);
  const yLineRef = useRef<HTMLElement | null>(null);
  const dotRef = useRef<HTMLElement | null>(null);
  const frameRef = useRef<number | null>(null);
  const pointRef = useRef({ x: -120, y: -120 });

  const ensureCursorNodes = useCallback(() => {
    const cursor = cursorRef.current;

    if (!cursor) {
      return false;
    }

    xLineRef.current ??= cursor.querySelector<HTMLElement>(".rain-cursor-x");
    yLineRef.current ??= cursor.querySelector<HTMLElement>(".rain-cursor-y");
    dotRef.current ??= cursor.querySelector<HTMLElement>(".rain-cursor-dot");

    return Boolean(xLineRef.current && yLineRef.current && dotRef.current);
  }, []);

  const flushCursor = useCallback(() => {
    frameRef.current = null;

    if (!ensureCursorNodes()) {
      return;
    }

    const x = Math.round(pointRef.current.x);
    const y = Math.round(pointRef.current.y);

    xLineRef.current!.style.transform = `translate3d(0, ${y}px, 0)`;
    yLineRef.current!.style.transform = `translate3d(${x}px, 0, 0)`;
    dotRef.current!.style.transform = `translate3d(${x}px, ${y}px, 0) translate(-50%, -50%)`;
  }, [ensureCursorNodes]);

  useEffect(() => {
    const onPointerMove = (event: globalThis.PointerEvent) => {
      pointRef.current.x = event.clientX;
      pointRef.current.y = event.clientY;

      if (frameRef.current === null) {
        frameRef.current = window.requestAnimationFrame(flushCursor);
      }
    };

    window.addEventListener("pointermove", onPointerMove, { passive: true });

    return () => {
      if (frameRef.current !== null) {
        window.cancelAnimationFrame(frameRef.current);
      }

      window.removeEventListener("pointermove", onPointerMove);
    };
  }, [flushCursor]);

  return { cursorRef };
}
