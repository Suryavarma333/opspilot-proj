"""FastAPI routes for browser-managed SNMP device inventory."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, HTTPException, Request, Response, status
from starlette.concurrency import run_in_threadpool

from .devices import (
    CredentialsUnavailableError,
    DeviceCreate,
    DeviceList,
    DeviceNotFoundError,
    DeviceRead,
    DeviceUpdate,
    DuplicateDeviceError,
    NetworkDeviceStore,
)


def _store(request: Request) -> NetworkDeviceStore:
    return cast(NetworkDeviceStore, request.app.state.opspilot.devices)


def create_devices_router() -> APIRouter:
    router = APIRouter(prefix="/api/devices", tags=["network devices"])

    @router.get("", response_model=DeviceList)
    async def list_devices(request: Request) -> DeviceList:
        return await run_in_threadpool(_store(request).list_devices)

    @router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
    async def create_device(payload: DeviceCreate, request: Request) -> DeviceRead:
        try:
            return await run_in_threadpool(_store(request).create_device, payload)
        except DuplicateDeviceError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except CredentialsUnavailableError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error

    @router.patch("/{device_id}", response_model=DeviceRead)
    async def update_device(device_id: str, payload: DeviceUpdate, request: Request) -> DeviceRead:
        try:
            return await run_in_threadpool(_store(request).update_device, device_id, payload)
        except DeviceNotFoundError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_device(device_id: str, request: Request) -> Response:
        deleted = await run_in_threadpool(_store(request).delete_device, device_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="network device not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router
