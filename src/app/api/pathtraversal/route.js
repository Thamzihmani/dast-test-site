/**
 * Path Traversal Test Endpoint
 *
 * VULNERABILITY: User-controlled filename from file upload / query param flows
 *   directly into fs.readFile and path.join without sanitization.
 *
 * DETECTOR:      taint-path_traversal
 * DETECTION:     req.files / req.query source → fs.readFile / path.join sink
 *
 * ENDPOINT:      GET /api/pathtraversal?file=safe.txt
 *                POST /api/pathtraversal (multipart with 'upload' field)
 */

export const runtime = 'nodejs'

import fs from 'fs'
import path from 'path'

// Pattern 1: req.query → fs.readFile (direct, same line)
export async function GET(request) {
  const file = new URL(request.url).searchParams.get('file')
  const data = fs.readFileSync(file)
  return Response.json({ data: data.toString() })
}

// Pattern 2: Express-style req.files → path.join (DVNA pattern)
export function expressStyleHandler(req, res) {
  var uploadPath = path.join('./uploads', req.files.upload.name)
  req.files.upload.mv(uploadPath, function(err) {
    if (err) return res.status(500).json(err)
    res.send('Uploaded')
  })
}

// Pattern 3: req.query → path.join → res.download (two-hop)
export function downloadHandler(req, res) {
  var filename = req.query.filename
  var filePath = path.join('./data/', filename)
  res.download(filePath)
}
