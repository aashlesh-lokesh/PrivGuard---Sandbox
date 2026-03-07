import path from 'path';
import { fileURLToPath } from 'url';
import CopyPlugin from 'copy-webpack-plugin';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default {
  mode: 'production',
  entry: {
    'detection-engine': './src/DetectionEngine.js',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].bundle.js',
    // Export as a library so the extension can import it
    library: {
      name: 'PrivGuardDetectionEngine',
      type: 'umd',
      export: 'default',
    },
    globalObject: 'this',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
        },
      },
    ],
  },
  resolve: {
    fallback: {
      // Tesseract.js needs these in browser context
      fs: false,
      path: false,
      crypto: false,
    },
  },
  plugins: [
    // Tesseract.js requires its worker and language data files
    new CopyPlugin({
      patterns: [
        {
          from: 'node_modules/tesseract.js/src/worker-script/browser/worker.min.js',
          to: 'tesseract-worker.min.js',
          noErrorOnMissing: true,
        },
      ],
    }),
  ],
  optimization: {
    // Keep Tesseract.js separate to allow lazy loading
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        tesseract: {
          test: /[\\/]node_modules[\\/]tesseract\.js[\\/]/,
          name: 'tesseract',
          chunks: 'all',
        },
        compromise: {
          test: /[\\/]node_modules[\\/]compromise[\\/]/,
          name: 'compromise',
          chunks: 'all',
        },
      },
    },
  },
};
