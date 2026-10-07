import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  serverExternalPackages: [
    "@vladmandic/face-api",
    "@tensorflow/tfjs",
    "@tensorflow/tfjs-core",
    "@tensorflow/tfjs-converter",
    "@tensorflow/tfjs-backend-cpu",
    "sharp",
  ],
};

export default nextConfig;
