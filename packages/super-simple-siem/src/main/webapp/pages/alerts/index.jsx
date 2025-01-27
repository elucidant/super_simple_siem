import React from 'react';
import layout from '@splunk/react-page';
import S3Table from '@splunk/s-3-table';
import {getUserTheme} from '@splunk/splunk-utils/themes';


// Get the user theme and render the S3Table using react-page.
getUserTheme().then((theme) => {
    layout(
        <S3Table userTheme={theme}/>
        ,
        {
            pageTitle: 'Alerts',
            hideFooter: false,
            layout: 'scrolling',
            theme
        });
});
