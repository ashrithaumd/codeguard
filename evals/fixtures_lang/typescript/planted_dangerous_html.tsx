// Planted: user-controlled HTML rendered without sanitising.
import React from "react";

export function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
