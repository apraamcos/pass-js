'use strict';

module.exports = {
  '*.ts': [
    'eslint --fix --quiet -f visualstudio',
    'prettier --write',
    'git add',
    'vitest related --run',
  ],
  '.env': ['git rm'],
  '*.{yaml,yml}': ['prettier --write', 'git add'],
  '*.{md,json}': ['prettier --write', 'git add'],

  '.codecov.yml': () =>
    'curl -f --silent --data-binary @.codecov.yml https://codecov.io/validate',
};
