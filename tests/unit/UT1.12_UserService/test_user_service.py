# Copyright 2026 Cloud-Dog, Viewdeck Engineering Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cloud_dog_idam.domain.models import User
from cloud_dog_idam.users.service import UserService


def test_user_service_crud() -> None:
    s = UserService()
    u = s.create(User(username="u", email="u@x"))
    assert s.get(u.user_id) is not None
    s.update(u.user_id, display_name="User")
    assert s.get(u.user_id).display_name == "User"


def test_user_service_delegates_to_repository() -> None:
    class Repo:
        def __init__(self) -> None:
            self.saved: list[User] = []

        def save(self, user: User) -> User:
            self.saved.append(user)
            return user

        def get(self, user_id: str) -> User | None:
            for item in self.saved:
                if item.user_id == user_id:
                    return item
            return None

        def update(self, user_id: str, changes: dict[str, object]) -> User:
            user = self.get(user_id)
            assert user is not None
            for key, value in changes.items():
                setattr(user, key, value)
            return user

        def search(self, term: str) -> list[User]:
            return [u for u in self.saved if term in u.username]

        def list_all(self) -> list[User]:
            return list(self.saved)

    repo = Repo()
    s = UserService(repository=repo)
    u = s.create(User(username="delegated", email="d@x"))
    assert repo.saved and repo.saved[0].user_id == u.user_id
