class DataHandler:
    def __init__(self, policy_data) -> None:
        self._policy_data = policy_data

    def needs_fetch_content(self) -> bool:
        return (
            self._policy_data.content_url and
            self._policy_data.content_type != "scap-security-guide"
        )
