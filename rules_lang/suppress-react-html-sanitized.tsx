import React from "react";
import DOMPurify from "dompurify";

export function Inline({ html }: { html: string }) {
  // ruleid: codeguard-suppress-react-html-sanitized
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function ViaConst({ body }: { body: string }) {
  const clean = DOMPurify.sanitize(body);
  // ruleid: codeguard-suppress-react-html-sanitized
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

export function CreateElement(props: { html: string }) {
  // ruleid: codeguard-suppress-react-html-sanitized
  return React.createElement("div", { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(props.html) } });
}

export function Raw({ html }: { html: string }) {
  // ok: codeguard-suppress-react-html-sanitized
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function SanitizedButRawRendered({ body }: { body: string }) {
  const clean = DOMPurify.sanitize(body);
  console.log(clean.length);
  // ok: codeguard-suppress-react-html-sanitized
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

export function Reassigned({ body }: { body: string }) {
  let shown = DOMPurify.sanitize(body);
  shown = body;
  // ok: codeguard-suppress-react-html-sanitized
  return <div dangerouslySetInnerHTML={{ __html: shown }} />;
}
