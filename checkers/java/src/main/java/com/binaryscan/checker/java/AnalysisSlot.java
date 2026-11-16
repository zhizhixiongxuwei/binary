package com.binaryscan.checker.java;

import java.util.concurrent.Semaphore;

/** Shared budget for source project analysis and the child SpotBugs JVM. */
final class AnalysisSlot {
    private AnalysisSlot() {}
    static final Semaphore HEAVY = new Semaphore(1);
}
