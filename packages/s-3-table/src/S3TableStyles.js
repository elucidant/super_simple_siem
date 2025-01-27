import styled from 'styled-components';
import { variables, mixins } from '@splunk/themes';

const Severity = styled.span<{ level: string }>`
    border: 1px solid transparent;
    border-radius: 4px;
    font-weight: 400;
    text-align: center;
    padding: 2px 2px;
    ${(props) => {
        switch (props.level) {
            case 'critical':
                return `
                    color: #fff;
                    background-color: #c9302c;
                    border-color: #c9302c;
                `;
            case 'high':
                return `
                    color: #fff;
                    background-color: #ec971f;
                    border-color: #ec971f;
                `;
        }
    }}
`;

export { Severity };
