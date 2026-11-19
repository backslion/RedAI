import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// 抽屉/对话框(Sheet/Dialog)的 onInteractOutside 关闭判定辅助。
//
// 背景:抽屉内的 Radix 弹层(Select 下拉、DropdownMenu、Popover 等)会 portal 到抽屉
// 之外。开着弹层时点遮罩/抽屉外想收起它,这一次 pointerdown 会被 Select 和 Sheet 两个
// DismissableLayer 同时处理;Select 先关闭且是 discrete 事件、React 会同步 flush,于是
// 轮到 Sheet 的处理器时弹层的 data-state 早已翻成 closed —— 在"当下"检测弹层是否打开
// 天然不可靠(实测已验证)。
//
// 正确做法:Radix 的 pointerdown 监听在冒泡阶段;我们在 capture 阶段(早于它)先把
// "此刻有没有弹层开着"记录下来,onInteractOutside 再读这个记录值来决定是否放行关闭。
function isRadixOverlayOpenNow(): boolean {
  if (typeof document === "undefined") return false;
  return !!document.querySelector(
    [
      "[data-slot='select-trigger'][data-state='open']",
      "[data-slot='select-content'][data-state='open']",
      "[role='listbox'][data-state='open']",
      "[data-radix-popper-content-wrapper]",
      "[aria-expanded='true'][data-state='open']",
    ].join(","),
  );
}

let overlayOpenAtLastPointerDown = false;
if (typeof document !== "undefined") {
  document.addEventListener(
    "pointerdown",
    () => {
      overlayOpenAtLastPointerDown = isRadixOverlayOpenNow();
    },
    true, // capture:抢在 Radix 冒泡阶段的 pointerdown 处理器之前记录
  );
}

// radixOverlayWasOpenAtPointerDown 返回"最近一次 pointerdown 发生时是否有 Radix 弹层
// 开着"。抽屉/对话框据此:开着弹层时点遮罩 → 只收弹层、不关自身。
export function radixOverlayWasOpenAtPointerDown(): boolean {
  return overlayOpenAtLastPointerDown;
}

// safeUUID 返回一个 UUID v4 字符串。
// 背景:crypto.randomUUID 与 navigator.clipboard 一样只在安全上下文(HTTPS / localhost)
// 可用;通过 IP + HTTP 访问局域网部署时它是 undefined,直接调用会让组件在渲染期抛
// TypeError 整页白屏(localhost 开发永远复现不了)。crypto.getRandomValues 不受此限制,
// 故降级用它拼 v4;连 getRandomValues 都没有(极老浏览器)才退到 Math.random。
export function safeUUID(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") {
    try {
      return c.randomUUID();
    } catch {
      // 继续走降级
    }
  }
  const b = new Uint8Array(16);
  if (c && typeof c.getRandomValues === "function") {
    c.getRandomValues(b);
  } else {
    for (let i = 0; i < 16; i += 1) b[i] = Math.floor(Math.random() * 256);
  }
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// copyText 把文本写入剪贴板,返回是否成功。
// 背景:navigator.clipboard 仅在安全上下文(HTTPS / localhost)可用;通过 IP + HTTP
// 访问时它为 undefined,此时降级到 execCommand("copy")。
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // 继续走降级方案
    }
  }
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

export const getInitials = (str: string): string => {
  if (typeof str !== "string" || !str.trim()) return "?";

  return (
    str
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map((word) => word[0])
      .join("")
      .toUpperCase() || "?"
  );
};

export function formatCurrency(
  amount: number,
  opts?: {
    currency?: string;
    locale?: string;
    minimumFractionDigits?: number;
    maximumFractionDigits?: number;
    noDecimals?: boolean;
  },
) {
  const { currency = "USD", locale = "en-US", minimumFractionDigits, maximumFractionDigits, noDecimals } = opts ?? {};

  const formatOptions: Intl.NumberFormatOptions = {
    style: "currency",
    currency,
    minimumFractionDigits: noDecimals ? 0 : minimumFractionDigits,
    maximumFractionDigits: noDecimals ? 0 : maximumFractionDigits,
  };

  return new Intl.NumberFormat(locale, formatOptions).format(amount);
}
