from org_fedora_oscap import common


class PolicyDataHandler:
    def __init__(self, policy_data):
        self._policy_data = policy_data

    def needs_fetch_content(self):
        return (
            self._policy_data.content_url and
            self._policy_data.content_type != "scap-security-guide"
        )

    def content_defined(self):
        return (
            self._policy_data.content_url or
            self._policy_data.content_type == "scap-security-guide"
        )

    def use_system_content(self):
        self._policy_data.clear_all()
        self._policy_data.content_type = "scap-security-guide"
        self._policy_data.content_path = common.get_ssg_path()

    def use_downloaded_content(self, content):
        preferred_content = content.get_preferred_content(
            self._policy_data.content_path)

        # We know that we have ended up with a datastream-like content,
        # but if we can't convert an archive to a datastream.
        # self._policy_data.content_type = "datastream"
        content_type = self._policy_data.content_type
        if content_type in ("archive", "rpm"):
            self._policy_data.content_path = str(
                preferred_content.relative_to(content.root))
        else:
            self._policy_data.content_path = str(preferred_content)

        preferred_tailoring = content.get_preferred_tailoring(
            self._policy_data.tailoring_path)
        if content.tailoring:
            if content_type in ("archive", "rpm"):
                self._policy_data.tailoring_path = str(
                    preferred_tailoring.relative_to(content.root))
            else:
                self._policy_data.tailoring_path = str(preferred_tailoring)

    def set_url(self, url):
        self._policy_data.content_url = url
        if url.endswith(".rpm"):
            self._policy_data.content_type = "rpm"
        elif any(url.endswith(arch_type) for arch_type in common.SUPPORTED_ARCHIVES):
            self._policy_data.content_type = "archive"
        else:
            self._policy_data.content_type = "datastream"
