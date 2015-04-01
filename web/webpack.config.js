module.exports = {
    entry: "./keytree.js",
    output: {
        path: __dirname,
        filename: "bundle.js"
    },
    module: {
        loaders: [
            { test: /\.js$/, exclude: /node_modules/, loader: 'babel-loader?experimental&optional=runtime'}
        ]
    }
};

