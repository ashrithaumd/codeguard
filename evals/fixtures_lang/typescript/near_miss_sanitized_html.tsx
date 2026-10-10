// Near miss: dangerouslySetInnerHTML, but on DOMPurify's output.
import React from "react";
import DOMPurify from "dompurify";

export function Comment({ body }: { body: string }) {
  const clean = DOMPurify.sanitize(body);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
