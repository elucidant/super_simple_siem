const path = require('path');
const { merge: webpackMerge } = require('webpack-merge');
const baseComponentConfig = require('@splunk/webpack-configs/component.config').default;

module.exports = webpackMerge(baseComponentConfig, {
    entry: {
        S3Table: path.join(__dirname, 'src/S3Table.jsx'),
    },
    output: {
        path: path.join(__dirname),
    },
});
