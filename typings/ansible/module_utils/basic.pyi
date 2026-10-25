from collections.abc import Mapping, Sequence
from typing import NoReturn

class AnsibleModule:
    params: Mapping[str, object]
    check_mode: bool

    def __init__(
        self,
        argument_spec: Mapping[str, object],
        *,
        required_if: Sequence[tuple[str, str, Sequence[str]]] | None = None,
        supports_check_mode: bool = False,
    ) -> None: ...
    def exit_json(self, **kwargs: object) -> NoReturn: ...
    def fail_json(self, msg: str, **kwargs: object) -> NoReturn: ...
