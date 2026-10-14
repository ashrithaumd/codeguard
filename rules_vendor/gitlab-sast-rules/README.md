# Vendored rules: GitLab sast-rules v2.10.1

Pinned, unmodified copies of GitLab's Semgrep rules for JavaScript/TypeScript, Go, Java and C#.
See NOTICE for the source, archive checksum and licenses. They are not loaded by the Python scan
path; they are used only for the languages they cover.

To update: download a new tag's archive, record its sha256 in NOTICE, copy only `*.yml` for these four
languages, and regenerate MANIFEST.sha256 with
`find javascript go java csharp -name '*.yml' | sort | xargs sha256sum > MANIFEST.sha256` (prepend the header).
