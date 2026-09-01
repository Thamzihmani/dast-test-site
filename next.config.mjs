/** @type {import('next').NextConfig} */
const nextConfig = {
  // Allow SSRF test endpoint to fetch any external URL
  async headers() {
    return [
      {
        // Apply to all routes — individual routes can override
        source: '/(.*)',
        headers: [
          // Intentionally weak default headers so detector fires on most pages
          { key: 'X-Powered-By', value: 'Next.js' },
        ],
      },
    ]
  },
}

export default nextConfig
