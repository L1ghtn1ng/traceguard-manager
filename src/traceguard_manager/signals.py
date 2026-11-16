"""In-process wake-up for live dashboard streams."""

import asyncio


class ChangeSignal:
    """Wakes waiting streams when new alerts are stored in this process.

    It carries no data: listeners re-read the database, so a missed or
    cross-worker notification only delays an update until the next poll.
    """

    def __init__(self) -> None:
        self._waiters: set[asyncio.Future[None]] = set()

    def notify(self) -> None:
        waiters, self._waiters = self._waiters, set()
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)

    async def wait(self) -> None:
        """Wait for the next notification. Callers bound the wait with ``asyncio.timeout``."""
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.add(waiter)
        try:
            await waiter
        finally:
            self._waiters.discard(waiter)
