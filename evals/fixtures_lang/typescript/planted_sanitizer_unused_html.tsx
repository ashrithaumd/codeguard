// Planted: the body is sanitized, but the raw body is what gets rendered.
import React from "react";
import DOMPurify from "dompurify";

export function Preview({ body }: { body: string }) {
  const clean = DOMPurify.sanitize(body);
  const words = clean.split(/\s+/).length;
  return (
    <section>
      <p>{words} words</p>
      <div dangerouslySetInnerHTML={{ __html: body }} />
    </section>
  );
}
