import { ReactNode, useState, useCallback } from "react"

import { motion, AnimatePresence } from "framer-motion"
import { useLayer, Arrow } from "react-laag"

import styles from "./AsyncButton.module.css"
import Button, { Props as ButtonProps } from "./Button"

export interface Props extends ButtonProps {
    onClick: () => Promise<unknown>,
    forceLoading?: boolean,
    errorPlacement?: import("react-laag/dist/PlacementType").PlacementType,
    children: ReactNode,
}

export default function AsyncButton(props: Props) {
    const [isAwaitingPromise, setIsAwaitingPromise] = useState(false)
    const isLoading = isAwaitingPromise || props.forceLoading
    const [errorMessage, setErrorMessage] = useState("")
    const clickHandler = props.onClick
    const onClick = useCallback(() => {
        if (!isLoading) {
            setIsAwaitingPromise(true)
            setErrorMessage("")

            const promise = clickHandler()

            if (promise instanceof Promise) {
                promise.catch(error => {
                    console.error("AsyncButton caught error", error)
                    setErrorMessage(error.message || error.toString())
                }).finally(() => {
                    setIsAwaitingPromise(false)
                })
            } else {
                console.error("AsyncButton onClick() must return a promise, but instead it returned", promise)
                setIsAwaitingPromise(false)
            }
        }
    }, [isLoading, clickHandler])
    const { triggerProps, layerProps, arrowProps, renderLayer } = useLayer({
        isOpen: errorMessage !== "",
        onOutsideClick: () => setErrorMessage(""),
        placement: props.errorPlacement ?? "top-center",
        triggerOffset: 8,
    })

    // TODO: prettier loading state

    return <Button
        {...props}
        onClick={onClick}
        {...triggerProps}
    >
        {isLoading ? "Loading..." : props.children}

        {renderLayer(
            <AnimatePresence>
                {errorMessage && <motion.div
                    className={styles.errorPopup}
                    initial={{ scaleX: 0.7, scaleY: 0, opacity: 0 }}
                    animate={{ scaleX: 1, scaleY: 1, opacity: 1 }}
                    exit={{ scaleX: 0.7, scaleY: 0, opacity: 0 }}
                    transition={{ type: "spring", duration: 0.2 }}
                    {...layerProps}
                >
                    <pre>{errorMessage}</pre>
                    <Arrow size={12} backgroundColor="#bb4444" {...arrowProps} />
                </motion.div>}
            </AnimatePresence>
        )}
    </Button>
}
