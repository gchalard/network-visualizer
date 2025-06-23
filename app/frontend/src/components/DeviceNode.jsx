import React, { memo } from "react";
import { Handle, Position } from "@xyflow/react";
import { FaQuestion, FaWindows, FaLinux } from "react-icons/fa";

export default memo(({ id, data, isConnectable}) => {

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

    return(
        <>
            <div>{getOsIcon(data.os_family)}</div>
            { data.type === 'source' && (
                <Handle type="source" position={Position.Right} isConnectable={isConnectable} />
            )}
            <div>{data.label}</div>
            <div>{id}</div>
            { data.type === 'target' && (
                <Handle type="target" position={Position.Left} isConnectable={isConnectable} />
            )}
        </>
    )
})