"""
sentry_github.plugin
~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2012 by the Sentry Team, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
import requests
from django import forms
from django.core.cache import cache
from django.utils.translation import ugettext_lazy as _
from sentry.plugins.bases.issue import IssuePlugin, NewIssueForm
from django.utils.safestring import mark_safe
from sentry.http import safe_urlopen, safe_urlread
from sentry.utils import json

import sentry_github


class NewGitHubIssueForm(NewIssueForm):

    assignee = forms.ChoiceField(required=False)

    def populate_with_assignees(self, assignees):
        choices = [(None, _('(nobody)')), ] + [(c['login'], '@%s' % c['login']) for c in assignees]
        self.fields['assignee'].choices = choices


class GitHubOptionsForm(forms.Form):
    # TODO: validate repo?
    repo = forms.CharField(label=_('Repository Name'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. getsentry/sentry'}),
        help_text=_('Enter your repository name, including the owner.'))


class GitHubPlugin(IssuePlugin):
    new_issue_form = NewGitHubIssueForm
    author = 'Sentry Team'
    author_url = 'https://github.com/getsentry/sentry'
    version = sentry_github.VERSION
    description = "Integrate GitHub issues by linking a repository to a project."
    resource_links = [
        ('Bug Tracker', 'https://github.com/getsentry/sentry-github/issues'),
        ('Source', 'https://github.com/getsentry/sentry-github'),
    ]

    slug = 'github'
    title = _('GitHub')
    conf_title = title
    conf_key = 'github'
    project_conf_form = GitHubOptionsForm
    auth_provider = 'github'

    def is_configured(self, request, project, **kwargs):
        return bool(self.get_option('repo', project))

    def get_new_issue_title(self, **kwargs):
        return 'Create GitHub Issue'

    def get_new_issue_form(self, request, group, event, **kwargs):
        """
        Return a Form for the "Create new issue" page.
        """
        form = super(GitHubPlugin, self).get_new_issue_form(request, group, event, **kwargs)
        form.populate_with_assignees(self.get_github_assignees(request, group.project))
        return form

    def get_github_assignees(self, request, project):
        """
        Return all project members also associated with their GitHub accounts

        The value is cached for 60 minutes
        """
        repo = self.get_option('repo', project)
        url = 'https://api.github.com/repos/%s/assignees' % repo
        cache_key = 'github_assignees:%s' % url
        result = cache.get(cache_key)

        if result is None:
            result = self.github_request(request, url)
            cache.set(cache_key, result, timeout=3600)
        return result

    def create_issue(self, request, group, form_data, **kwargs):
        # TODO: support multiple identities via a selection input in the form?
        repo = self.get_option('repo', group.project)
        url = 'https://api.github.com/repos/%s/issues' % (repo,)

        json_data = {
          "title": form_data['title'],
          "body": form_data['description'],
          "assignee": form_data['assignee'],
          # "milestone": 1,
          # "labels": [
          #   "Label1",
          #   "Label2"
          # ]
        }
        json_resp = self.github_request(request, url, json=json_data)
        issue_id = json_resp['number']
        assignee = form_data['assignee']
        if assignee:
            return '%s:%s' % (issue_id, assignee)
        else:
            return issue_id

    def get_issue_label(self, group, issue_id, **kwargs):
        issue_id, assignee = self.extract_assignee(issue_id)
        issue_html = '<i class="fa fa-github"></i> GH-%s' % issue_id
        if assignee:
            assignee_html = ' assigned to @%s' % assignee
        else:
            assignee_html = ''
        return mark_safe('%s%s' % (issue_html, assignee_html))

    def get_issue_url(self, group, issue_id, **kwargs):
        # XXX: get_option may need tweaked in Sentry so that it can be pre-fetched in bulk
        repo = self.get_option('repo', group.project)
        issue_id, assignee = self.extract_assignee(issue_id)
        return 'https://github.com/%s/issues/%s' % (repo, issue_id)

    def github_request(self, request, url, **kwargs):
        """
        Make a GitHub request on behalf of the logged in user. Return JSON
        response on success or raise forms.ValidationError on any exception
        """
        auth = self.get_auth_for_user(user=request.user)
        if auth is None:
            raise forms.ValidationError(_('You have not yet associated GitHub with your account.'))

        headers = kwargs.pop('headers', None) or {}
        headers['Authorization'] = 'token %s' % auth.tokens['access_token']
        try:
            req = safe_urlopen(url, headers=headers, **kwargs)
            body = safe_urlread(req)
        except requests.RequestException as e:
            msg = unicode(e)
            raise forms.ValidationError(_('Error communicating with GitHub: %s') % (msg,))

        try:
            json_resp = json.loads(body)
        except ValueError as e:
            msg = unicode(e)
            raise forms.ValidationError(_('Error communicating with GitHub: %s') % (msg,))

        if req.status_code > 399:
            raise forms.ValidationError(json_resp['message'])

        return json_resp

    def extract_assignee(self, issue_id):
        """
        Split issue id to pair (issue_id, assignee). If there's no assignee,
        return (issue_id, None)
        """
        issue_id = issue_id or ''
        if ':' in issue_id:
            return issue_id.split(':', 1)
        return issue_id, None
