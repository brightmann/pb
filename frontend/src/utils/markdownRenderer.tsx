/**
 * Markdown 渲染增强工具
 * 功能：
 * - 链接在新标签页打开
 * - 增强的代码高亮
 * - 表格、任务列表等 GitHub 风格渲染
 * - 原始 HTML 渲染（DOMPurify 白名单净化，禁止 script/style/危险协议，iframe 仅 https）
 * - YouTube 嵌入视频（youtube.com / youtube-nocookie.com embed 地址渲染为播放器）
 *
 * 主题适配规范（v2.0）：
 * - 所有颜色使用语义化 token（text-foreground / text-muted-foreground / bg-card 等）
 * - 代码块区域固定深色背景，保障可读性
 * - 主色调引用使用 text-primary / bg-primary / border-primary
 *
 * @version 2.0.0 - 完整主题适配，保留所有原始功能
 */

import DOMPurify from 'dompurify';
import type { Components } from 'react-markdown';


/**
 * YouTube 嵌入视频支持
 * 只允许 youtube.com / youtube-nocookie.com 的 embed 地址，
 * 其它来源的 iframe 不会被转换，也不会被渲染
 */
const YOUTUBE_EMBED_PREFIXES = [
  'https://www.youtube.com/embed/',
  'https://www.youtube-nocookie.com/embed/',
];

export function isYouTubeEmbedUrl(url: string | undefined | null): boolean {
  return !!url && YOUTUBE_EMBED_PREFIXES.some((prefix) => url.startsWith(prefix));
}

/**
 * 将 Markdown 中的 YouTube iframe 嵌入代码转换为链接标记，
 * 由 LinkComponent 渲染为 <iframe>；其它 iframe 保持原样（默认不会被渲染）
 */
export function transformYouTubeIframes(markdown: string): string {
  if (!markdown) return markdown;
  return markdown.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, (block) => {
    const srcMatch = block.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
    const src = srcMatch?.[1];
    if (src && isYouTubeEmbedUrl(src)) {
      return `[${src}](${src})`;
    }
    return block;
  });
}

/**
 * 通用原始 HTML 支持（安全净化后渲染）
 *
 * 作者可在 Markdown 中直接书写 HTML（iframe 嵌入、表格、排版标签等）。
 * 渲染前先用 DOMPurify 白名单净化：
 * - 禁止 script / style / form / object / embed 等活动内容标签
 * - 禁止 on* 事件属性、javascript: 等危险协议（DOMPurify 默认）
 * - iframe 仅允许 https 地址（支持 YouTube 以外的 https 嵌入）
 * 净化后的 HTML 编码为 rawhtml:// 占位链接，由 LinkComponent 还原渲染。
 * 净化后被完全移除的内容（如 <script>）不会出现在页面中。
 */
const RAW_HTML_PROTOCOL = 'rawhtml://';

/** 成对标签：<tag ...>...</tag>（允许跨行内容） */
const RAW_HTML_PAIR_RE = /<([a-zA-Z][a-zA-Z0-9-]*)\b[^>]*>[\s\S]*?<\/\1\s*>/g;
/** 单个标签：<br>、<img ...>、<hr/> 等 */
const RAW_HTML_SINGLE_RE = /<[a-zA-Z][a-zA-Z0-9-]*\b[^>]*\/?>/g;
/** 代码区域：围栏代码块与行内代码，其中的 HTML 是示例文本，不应被渲染 */
const CODE_REGION_RE = /(```[\s\S]*?(?:```|$)|~~~[\s\S]*?(?:~~~|$)|`[^`\n]*`)/g;

const RAW_HTML_SANITIZE_CONFIG = {
  // 在 DOMPurify 默认白名单基础上补充 iframe（默认不允许）
  ADD_TAGS: ['iframe'],
  ADD_ATTR: ['allow', 'allowfullscreen', 'frameborder', 'scrolling', 'referrerpolicy', 'loading', 'id', 'align', 'target', 'rel'],
  // 显式禁止活动内容与表单标签（大部分默认已禁止，这里声明意图）
  FORBID_TAGS: ['script', 'style', 'form', 'input', 'button', 'select', 'textarea', 'object', 'embed', 'meta', 'link', 'base'],
  FORBID_ATTR: ['srcdoc'],
};

let rawHtmlHookRegistered = false;

/** 注册一次性净化钩子：iframe 仅允许 https src；新窗口链接补充 rel 防篡改 */
function ensureRawHtmlHook(): void {
  if (rawHtmlHookRegistered) return;
  DOMPurify.addHook('afterSanitizeAttributes', (node: Element) => {
    if (node.tagName === 'IFRAME') {
      const src = node.getAttribute('src') || '';
      if (!/^https:\/\//i.test(src)) {
        node.remove();
      }
    }
    if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
      node.setAttribute('rel', 'noopener noreferrer');
    }
  });
  rawHtmlHookRegistered = true;
}

/** UTF-8 安全 base64 编码（分块避免大字符串栈溢出） */
function encodeUtf8Base64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

/** UTF-8 安全 base64 解码，失败返回空串 */
function decodeUtf8Base64(encoded: string): string {
  try {
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

/** 只对代码区域以外的文本应用转换 */
function transformOutsideCode(markdown: string, fn: (segment: string) => string): string {
  return markdown
    .split(CODE_REGION_RE)
    .map((part, index) => (index % 2 === 1 ? part : fn(part)))
    .join('');
}

/**
 * 处理 Markdown 中的原始 HTML：
 * 1. 代码区域外的 YouTube iframe 先转为链接，由 LinkComponent 渲染为播放器；
 * 2. 其余 HTML 经 DOMPurify 白名单净化后编码为 rawhtml:// 占位链接，
 *    由 LinkComponent 还原为净化后的 HTML 渲染。
 */
export function transformRawHtml(markdown: string): string {
  if (!markdown) return markdown;
  ensureRawHtmlHook();
  return transformOutsideCode(markdown, (segment) => {
    const encodeChunk = (chunk: string): string => {
      const clean = DOMPurify.sanitize(chunk, RAW_HTML_SANITIZE_CONFIG).trim();
      if (!clean) return '';
      return `[html](${RAW_HTML_PROTOCOL}${encodeUtf8Base64(clean)})`;
    };
    return transformYouTubeIframes(segment)
      .replace(RAW_HTML_PAIR_RE, encodeChunk)
      .replace(RAW_HTML_SINGLE_RE, encodeChunk);
  });
}

/**
 * 自定义链接组件 - 在新标签页打开
 */
export const LinkComponent: Components['a'] = ({ node, children, href, ...props }) => {
  // 净化后的原始 HTML 占位链接，还原渲染
  if (href?.startsWith(RAW_HTML_PROTOCOL)) {
    const html = decodeUtf8Base64(href.slice(RAW_HTML_PROTOCOL.length));
    if (!html) return null;
    return <span className="raw-html" dangerouslySetInnerHTML={{ __html: html }} />;
  }

  // YouTube 嵌入链接渲染为视频播放器
  if (isYouTubeEmbedUrl(href)) {
    return (
      <span className="relative block w-full my-4 overflow-hidden rounded-lg border border-border" style={{ paddingTop: '56.25%' }}>
        <iframe
          src={href}
          title="YouTube video"
          className="absolute inset-0 h-full w-full"
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
          referrerPolicy="strict-origin-when-cross-origin"
          allowFullScreen
        />
      </span>
    );
  }

  const isExternal = href?.startsWith('http://') || href?.startsWith('https://');
  const baseClass = "text-primary hover:opacity-80 underline underline-offset-2 transition-opacity";

  if (isExternal) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={baseClass} {...props}>
        {children}
        <svg className="inline-block w-3.5 h-3.5 ml-0.5 opacity-70" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
        </svg>
      </a>
    );
  }

  return <a href={href} className={baseClass} {...props}>{children}</a>;
};

/**
 * 自定义代码块组件 - 增强的代码高亮
 * 代码块固定深色背景保障可读性，行内代码跟随主题
 */
export const CodeComponent: Components['code'] = ({ node, inline, className, children, ...props }: any) => {
  const match = /language-(\w+)/.exec(className || '');
  const language = match ? match[1] : '';

  if (!inline && match) {
    return (
      <div className="relative group my-4">
        <div className="flex items-center justify-between px-4 py-2 bg-slate-800 rounded-t-lg border-b border-slate-700">
          <span className="text-xs text-slate-400 uppercase font-medium tracking-wider">{language}</span>
          <button
            onClick={() => navigator.clipboard.writeText(String(children).replace(/\n$/, ''))}
            className="text-xs text-slate-400 hover:text-slate-100 transition-colors flex items-center gap-1"
            title="复制代码"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            复制
          </button>
        </div>
        <pre className="!mt-0 !rounded-t-none bg-slate-900 text-slate-100 p-4 rounded-b-lg overflow-x-auto">
          <code className={className} {...props}>{children}</code>
        </pre>
      </div>
    );
  }

  return (
    <code className="bg-muted text-foreground px-1.5 py-0.5 rounded text-sm font-mono border border-border" {...props}>
      {children}
    </code>
  );
};

/**
 * 从 React children 中提取纯文本
 */
function extractTextFromChildren(children: any): string {
  if (typeof children === 'string') return children;
  if (typeof children === 'number') return String(children);
  if (Array.isArray(children)) {
    return children.map(extractTextFromChildren).join('');
  }
  if (children?.props?.children) {
    return extractTextFromChildren(children.props.children);
  }
  return String(children || '');
}

/**
 * 生成 slug id
 * 支持中文、英文、数字等多种字符
 */
function generateSlug(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\u4e00-\u9fa5a-zA-Z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * 自定义标题组件 - 添加锚点链接
 */
export const HeadingComponent = (level: number): Components[`h${1 | 2 | 3 | 4 | 5 | 6}`] => {
  return ({ node, children, ...props }: any) => {
    const Tag = `h${level}` as keyof JSX.IntrinsicElements;
    const textContent = extractTextFromChildren(children);
    const id = generateSlug(textContent);

    const sizeClasses = {
      1: 'text-3xl mt-8 mb-4',
      2: 'text-2xl mt-6 mb-3',
      3: 'text-xl mt-5 mb-2',
      4: 'text-lg mt-4 mb-2',
      5: 'text-lg mt-4 mb-2',
      6: 'text-lg mt-4 mb-2',
    };

    return (
      <Tag
        id={id}
        className={`group flex items-center gap-2 text-foreground font-bold scroll-mt-20 ${sizeClasses[level as keyof typeof sizeClasses]}`}
        {...props}
      >
        {children}
        <a
          href={`#${id}`}
          onClick={(e) => {
            e.preventDefault();
            const offset = 100;
            const element = document.getElementById(id);
            if (element) {
              const elementPosition = element.getBoundingClientRect().top + window.scrollY;
              window.scrollTo({ top: elementPosition - offset, behavior: 'smooth' });
              window.location.hash = id;
            }
          }}
          className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-primary transition-opacity cursor-pointer"
          title="复制链接"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
        </a>
      </Tag>
    );
  };
};

/**
 * 自定义表格组件
 */
export const TableComponent: Components['table'] = ({ node, children, ...props }) => (
  <div className="overflow-x-auto my-6">
    <table className="min-w-full border-collapse border border-border" {...props}>{children}</table>
  </div>
);

export const TableHeadComponent: Components['thead'] = ({ node, children, ...props }) => (
  <thead className="bg-muted" {...props}>{children}</thead>
);

export const TableRowComponent: Components['tr'] = ({ node, children, ...props }) => (
  <tr className="border-b border-border hover:bg-accent/50 transition-colors" {...props}>{children}</tr>
);

export const TableCellComponent: Components['td'] = ({ node, children, ...props }) => (
  <td className="px-4 py-3 border border-border text-foreground" {...props}>{children}</td>
);

export const TableHeaderCellComponent: Components['th'] = ({ node, children, ...props }) => (
  <th className="px-4 py-3 border border-border text-left font-semibold text-foreground" {...props}>{children}</th>
);

/**
 * 自定义引用块组件
 */
export const BlockquoteComponent: Components['blockquote'] = ({ node, children, ...props }) => (
  <blockquote className="border-l-4 border-primary pl-4 py-2 my-6 bg-primary/5 rounded-r-lg text-muted-foreground italic" {...props}>
    {children}
  </blockquote>
);

/**
 * 自定义列表组件
 */
export const ListComponent: Components['ul'] = ({ node, children, ...props }) => (
  <ul className="list-disc list-inside my-4 space-y-1 text-foreground" {...props}>{children}</ul>
);

export const OrderedListComponent: Components['ol'] = ({ node, children, ...props }) => (
  <ol className="list-decimal list-inside my-4 space-y-1 text-foreground" {...props}>{children}</ol>
);

export const ListItemComponent: Components['li'] = ({ node, children, ...props }) => (
  <li className="ml-4" {...props}>{children}</li>
);

/**
 * 自定义任务列表组件
 */
export const TaskListComponent: Components['input'] = ({ node, checked, ...props }: any) => (
  <input
    type="checkbox"
    checked={checked}
    readOnly
    className="mr-2 w-4 h-4 accent-primary rounded border-border focus:ring-primary/50"
    {...props}
  />
);

/**
 * 自定义段落组件
 */
export const ParagraphComponent: Components['p'] = ({ node, children, ...props }) => (
  <p className="my-4 leading-relaxed text-foreground" {...props}>{children}</p>
);

/**
 * 自定义分割线组件
 */
export const HorizontalRuleComponent: Components['hr'] = ({ node, ...props }) => (
  <hr className="my-8 border-t-2 border-border" {...props} />
);

/**
 * 自定义图片组件
 */
export const ImageComponent: Components['img'] = ({ node, src, alt, ...props }) => (
  <figure className="my-6">
    <img
      src={src}
      alt={alt}
      className="max-w-full h-auto rounded-lg shadow-md mx-auto border border-border"
      loading="lazy"
      {...props}
    />
    {alt && (
      <figcaption className="text-center text-sm text-muted-foreground mt-2">{alt}</figcaption>
    )}
  </figure>
);

/**
 * 获取所有自定义组件
 */
export function getMarkdownComponents(): Components {
  return {
    a: LinkComponent,
    code: CodeComponent,
    h1: HeadingComponent(1),
    h2: HeadingComponent(2),
    h3: HeadingComponent(3),
    h4: HeadingComponent(4),
    h5: HeadingComponent(5),
    h6: HeadingComponent(6),
    table: TableComponent,
    thead: TableHeadComponent,
    tr: TableRowComponent,
    td: TableCellComponent,
    th: TableHeaderCellComponent,
    blockquote: BlockquoteComponent,
    ul: ListComponent,
    ol: OrderedListComponent,
    li: ListItemComponent,
    input: TaskListComponent,
    p: ParagraphComponent,
    hr: HorizontalRuleComponent,
    img: ImageComponent,
  };
}

/**
 * 目录项类型
 */
export interface TocItem {
  level: number;
  text: string;
  id: string;
}

/**
 * 生成目录（Table of Contents）
 */
export function generateToc(content: string): TocItem[] {
  const toc: TocItem[] = [];
  const headingRegex = /^(#{1,6})\s+(.+)$/gm;
  let match;

  while ((match = headingRegex.exec(content)) !== null) {
    const level = match[1].length;
    const text = match[2].trim();
    const id = generateSlug(text);
    toc.push({ level, text, id });
  }

  return toc;
}

/**
 * markdownComponents - 向后兼容别名
 * 等同于 getMarkdownComponents() 的返回值
 */
export const markdownComponents: Components = {
  a: LinkComponent,
  code: CodeComponent,
  h1: HeadingComponent(1),
  h2: HeadingComponent(2),
  h3: HeadingComponent(3),
  h4: HeadingComponent(4),
  h5: HeadingComponent(5),
  h6: HeadingComponent(6),
  table: TableComponent,
  thead: TableHeadComponent,
  tr: TableRowComponent,
  td: TableCellComponent,
  th: TableHeaderCellComponent,
  blockquote: BlockquoteComponent,
  ul: ListComponent,
  ol: OrderedListComponent,
  li: ListItemComponent,
  input: TaskListComponent,
  p: ParagraphComponent,
  hr: HorizontalRuleComponent,
  img: ImageComponent,
};
