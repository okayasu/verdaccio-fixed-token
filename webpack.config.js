const path = require("path");
const nodeExternals = require("webpack-node-externals");

module.exports = {
  mode: "development",
  entry: "./src/index.ts",
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: "ts-loader",
      },
    ],
  },
  target: "node",
  output: {
    path: path.join(__dirname, "lib"),
    filename: "index.js",
  },
  resolve: {
    extensions: [".ts", ".js"],
  },
  externals: [nodeExternals()],
};
