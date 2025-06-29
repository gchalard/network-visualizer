import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { FaQuestion, FaWindows, FaLinux } from "react-icons/fa";
import { useNavigate } from "react-router-dom";

export default memo(({ id, data, isConnectable }) => {

    const navigate = useNavigate();

    const getOsIcon = (os) => {
        switch (os) {
            case 'Windows':
                return <FaWindows />
            case 'Linux':
                return <FaLinux />
            default:
                return <FaQuestion />
        }
    }

    const onClick = () => {
        console.log(data.device)
        navigate(`/device/${data.device.ip}`, { state: { nodeData: data.device } })
    }

    return(
        <div onClick={onClick} style={{ cursor: 'pointer'}}>
            <div>{getOsIcon(data.device.os_family)}</div>
            { data.type === 'source' && (
                <Handle type="source" position={Position.Right} isConnectable={isConnectable} />
            )}
            <div>{data.label}</div>
            <div>{id}</div>
            { data.type === 'target' && (
                <Handle type="target" position={Position.Left} isConnectable={isConnectable} />
            )}
        </div>
    )
})